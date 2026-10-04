"""
Faithful re-implementation of the pieces of the Adjust signature pipeline that are
reproducible off-device.

What this module CAN do (pure Python, no device):
  * Reproduce the canonical string that gets HMAC'd
    (HashMap bucket order verified against a real JVM: 40/40 cases)
  * HMAC-SHA256 over that canonical string, given the raw key bytes
  * Assemble the Authorization header with algorithm="adj9"

VERIFIED AGAINST THE 5.0.0 BYTECODE (javap on com.adjust.sdk.sig.u2), not guessed:
  LinkedHashMap out = new LinkedHashMap<>(activityParams);   // source order kept
  out.put(globalParams...);  out.put("adj_verification", ...);
  byte[] hmac = keystore.sign(out.toString().getBytes(UTF-8));
  header = String.format("Signature %s,%s,%s,%s,%s,%s", ...)  // 6 fields, fixed order
So the canonical string is a LinkedHashMap.toString() -- but its PREFIX is a copy of
the SDK's source HashMap, which IS in bucket order. Both pieces are needed.

What it CANNOT do (do not let anyone tell you otherwise):
  * Obtain the signing key on API >= 23. It is an AndroidKeyStore (TEE/keymint)
    HmacSHA256 key, alias "key2", and getEncoded() returns null.
  * Reproduce nSign()'s output. The native lib does NOT compute it in-process: it
    IPCs to keystore2/keymint over /dev/binder and returns a 176-byte blob that is
    different on every call for identical inputs (per-call randomness in the
    keystore). There is no AES table and no ARMv8 crypto instruction in libsigner.so.

So this module is: canonicalisation + HMAC + header assembly, with a pluggable
backend for the final native step. The backend that actually works today is a
device oracle (frida RPC into Signer.sign()); see DeviceOracleBackend.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
from typing import Iterable, Mapping, Sequence, Tuple

# --------------------------------------------------------------------------------------
# Java primitives
# --------------------------------------------------------------------------------------

MASK32 = 0xFFFFFFFF


def _to_signed32(u: int) -> int:
    return u - 0x100000000 if u & 0x80000000 else u


def java_string_hash_code(s: str) -> int:
    """java.lang.String.hashCode(): 32-bit signed, over UTF-16 code units."""
    h = 0
    for ch in s:
        cu = ord(ch)
        if cu > 0xFFFF:  # surrogate pair -> two code units
            cu -= 0x10000
            for part in (0xD800 + (cu >> 10), 0xDC00 + (cu & 0x3FF)):
                h = (h * 31 + part) & MASK32
            continue
        h = (h * 31 + cu) & MASK32
    return _to_signed32(h)


def spread(h: int) -> int:
    """java.util.HashMap.hash(key): h ^ (h >>> 16) in 32-bit unsigned space."""
    u = h & MASK32
    return u ^ (u >> 16)


def table_size_for(cap: int) -> int:
    """java.util.HashMap.tableSizeFor - next power of two >= cap."""
    n = 1
    while n < cap:
        n <<= 1
    return n


# --------------------------------------------------------------------------------------
# HashMap iteration order
# --------------------------------------------------------------------------------------

TREEIFY_THRESHOLD = 8
MIN_TREEIFY_CAPACITY = 64


class TreeifyUnsupported(RuntimeError):
    """
    Java 8 treeifies a bin once it hits 9 nodes with table length >= 64, and a
    treeified bin iterates ROOT-FIRST instead of in insertion order -- which this
    port does not model.

    Measured on the real 52-field Adjust parameter map: largest bin = 4, so this
    is unreachable in practice. Raised loudly rather than returning a wrong
    canonical string.
    """


class _Node:
    __slots__ = ("key", "value", "hash", "next")

    def __init__(self, key, value, h):
        self.key, self.value, self.hash, self.next = key, value, h, None


class JavaHashMap:
    """
    Just enough of java.util.HashMap (Java 8 / Android) to reproduce
    toString() ordering. Values are stored as strings, matching the
    Map<String,String> the SDK signs.
    """

    def __init__(self, initial_capacity: int = 16, strict: bool = True):
        self.cap = table_size_for(initial_capacity) if initial_capacity else 16
        self.table: list = [None] * self.cap
        self.size = 0
        self.threshold = int(self.cap * 0.75)
        self.strict = strict  # raise on treeification instead of guessing
        self.max_bin = 0
        self.treeified = False

    # -- internals ---------------------------------------------------------------
    def _resize(self):
        old_cap = self.cap
        old_tab = self.table
        new_cap = old_cap << 1
        new_tab: list = [None] * new_cap
        for j in range(old_cap):
            head = old_tab[j]
            if head is None:
                continue
            lo_head = lo_tail = None
            hi_head = hi_tail = None
            e = head
            while e is not None:
                nxt = e.next
                e.next = None
                if (e.hash & old_cap) == 0:
                    if lo_tail is None:
                        lo_head = e
                    else:
                        lo_tail.next = e
                    lo_tail = e
                else:
                    if hi_tail is None:
                        hi_head = e
                    else:
                        hi_tail.next = e
                    hi_tail = e
                e = nxt
            new_tab[j] = lo_head
            new_tab[j + old_cap] = hi_head
        self.table = new_tab
        self.cap = new_cap
        self.threshold = int(new_cap * 0.75)

    def put(self, key: str, value):
        h = spread(java_string_hash_code(key))
        idx = h & (self.cap - 1)
        e = self.table[idx]
        while e is not None:
            if e.hash == h and e.key == key:
                e.value = value  # replacement: iteration order unchanged
                return
            e = e.next
        # Java 8 appends at the TAIL of the bin (Java 7 inserted at the head --
        # getting this wrong silently flips order inside every colliding bucket).
        node = _Node(key, value, h)
        bin_len = 1
        if self.table[idx] is None:
            self.table[idx] = node
        else:
            e = self.table[idx]
            bin_len += 1
            while e.next is not None:
                e = e.next
                bin_len += 1
            e.next = node
        self.max_bin = max(self.max_bin, bin_len)
        # Java calls treeifyBin() once a bin reaches TREEIFY_THRESHOLD nodes:
        #   - table < 64 slots -> treeifyBin() just calls resize() (modelled here)
        #   - table >= 64      -> the bin becomes a red-black tree and iterates
        #                         ROOT-FIRST, which we do NOT model (see guard)
        # Empirically confirmed against a real JVM: with all keys colliding, the
        # first divergence from insertion order appears exactly when this fires.
        if bin_len >= TREEIFY_THRESHOLD:
            if self.cap < MIN_TREEIFY_CAPACITY:
                self._resize()
            else:
                self.treeified = True
                msg = (f"bin reached {bin_len} nodes at capacity {self.cap}: Java "
                       f"treeifies here and iterates root-first, and nodes inserted "
                       f"into a tree bin are linked after their parent. This port "
                       f"cannot model that. Real Adjust maps peak at 4 nodes/bin, so "
                       f"this means your key set is pathological. "
                       f"Pass strict=False to proceed anyway.")
                if self.strict:
                    raise TreeifyUnsupported(msg)
        self.size += 1
        if self.size > self.threshold:
            self._resize()
        # NOTE: Java 8 also treeifies bins of >= 8 nodes when cap >= 64, but a
        # treeified bin still iterates in its linked-list (insertion) order, so
        # ordering is unaffected. Nothing to simulate here.

    # -- what we actually need ---------------------------------------------------
    def items_in_iteration_order(self) -> Iterable[Tuple[str, object]]:
        for j in range(self.cap):
            e = self.table[j]
            while e is not None:
                yield e.key, e.value
                e = e.next

    def to_java_string(self) -> str:
        """java.util.AbstractMap.toString(): {k=v, k=v} with null -> "null"."""
        parts = []
        for k, v in self.items_in_iteration_order():
            parts.append(f"{k}={'null' if v is None else v}")
        return "{" + ", ".join(parts) + "}"


def canonical_string(
    params: Mapping[str, object] | Sequence[Tuple[str, object]],
    initial_capacity: int = 16,
    strict: bool = True,
) -> str:
    """
    Build the exact string the SDK HMACs.

    `params` must be in the SDK's real *insertion* order (Python dicts / **kwargs
    preserve it). Bucket order -- and therefore the canonical string -- depends on
    it, so an out-of-order dict gives a wrong signature even with the right key.

    `initial_capacity`: the capacity the Java HashMap was constructed with.
    The Adjust SDK builds these maps with `new HashMap<>()` (16) and grows them,
    which for real packages lands at capacity 64. Use 64 unless you know better --
    capacity changes bucket indices and hence the whole ordering.
    """
    pairs = params.items() if isinstance(params, Mapping) else params
    m = JavaHashMap(initial_capacity, strict=strict)
    for k, v in pairs:
        m.put(k, v)
    return m.to_java_string()


def canonical_bytes(params, initial_capacity: int = 16, strict: bool = True) -> bytes:
    """canonical string -> UTF-8 bytes (the SDK does getBytes(UTF_8))."""
    return canonical_string(params, initial_capacity, strict).encode("utf-8")


# --------------------------------------------------------------------------------------
# HMAC + header
# --------------------------------------------------------------------------------------

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return _hmac.new(key, message, hashlib.sha256).digest()


def v5_map_order(
    activity_params: Mapping[str, object],
    global_params: Mapping[str, object] | None = None,
    adj_verification: str | None = None,
    source_capacity: int = 16,
) -> list[Tuple[str, object]]:
    """
    Reproduce the iteration order of the LinkedHashMap that u2 signs.

    Read off com.adjust.sdk.sig.u2 (signature SDK 5.0.0):
      LinkedHashMap out = new LinkedHashMap<>(activityParams);   // copy -> keeps
                                                                 // SOURCE order
      for (k : globalParamKeys) out.put(k, globalParams.get(k)); // appended
      out.put("adj_verification", o3.a(new a0()));               // appended
      byte[] hmac = keystore.sign(out.toString().getBytes(UTF-8));

    So: the prefix is the *source* map's order (a HashMap -> bucket order, which is
    what JavaHashMap below models), then globals in their own order, then
    adj_verification. Re-putting an existing key replaces the value but keeps the
    ORIGINAL position -- handled here.
    """
    src = JavaHashMap(source_capacity)
    for k, v in activity_params.items():
        src.put(k, v)
    ordered = list(src.items_in_iteration_order())

    def upsert(pairs, k, v):
        for i, (kk, _) in enumerate(pairs):
            if kk == k:
                pairs[i] = (k, v)
                return
        pairs.append((k, v))

    for k, v in (global_params or {}).items():
        upsert(ordered, k, v)
    if adj_verification is not None:
        upsert(ordered, "adj_verification", adj_verification)
    return ordered


def canonical_string_ordered(pairs: Sequence[Tuple[str, object]]) -> str:
    """LinkedHashMap.toString(): insertion order, no bucket reordering."""
    return "{" + ", ".join(
        f"{k}={'null' if v is None else v}" for k, v in pairs
    ) + "}"


def canonical_string_v5(
    activity_params: Mapping[str, object],
    global_params: Mapping[str, object] | None = None,
    adj_verification: str | None = None,
    source_capacity: int = 16,
) -> str:
    """The exact string signature SDK 5.x HMACs."""
    return canonical_string_ordered(
        v5_map_order(activity_params, global_params, adj_verification, source_capacity)
    )


def build_authorization_header(
    signature_b64: str,
    adj_signing_id: str,
    headers_id: str,
    algorithm: str,
    native_version: str,
    adj_verification: str | None = None,
) -> str:
    """
    The header u2 builds: String.format("Signature %s,%s,%s,%s,%s,%s", ...) where
    each %s is String.format("%s=\\"%s\\"", key, value).

    Field ORDER IS FIXED:

        signature, adj_signing_id, algorithm, headers_id,
        native_version, adj_verification

    NOTE: `algorithm` comes BEFORE `headers_id`. An earlier revision of this file
    had them swapped (headers_id first) -- that was wrong. Verified two ways:

      1. reference AAR 5.0.0, com/adjust/sdk/sig/u2.a(LinkedHashMap, byte[]):
         filled array slots are [0]=signature [1]=adj_signing_id
         [2]=algorithm(slot4) [3]=headers_id(slot3) [4]=native_version(slot0)
         [5]=adj_verification(slot5)
      2. the app's own classes3.dex, u2.a at 0x36a97c:
         filled-new-array/range {v14,v15,v16,v17,v18,v19} where
         v14=signature v15=adj_signing_id v16=algorithm v17=headers_id
         v18=native_version v19=adj_verification

    3.x differs only by having no adj_verification (5 fields).
    """
    head = (
        f'Signature signature="{signature_b64}",'
        f'adj_signing_id="{adj_signing_id}",'
        f'algorithm="{algorithm}",'
        f'headers_id="{headers_id}",'
        f'native_version="{native_version}"'
    )
    if adj_verification is not None:
        head += f',adj_verification="{adj_verification}"'
    return head


# --------------------------------------------------------------------------------------
# adj_verification
# --------------------------------------------------------------------------------------

# com.adjust.sdk.sig.s2.a -- 19-byte repeating XOR key.
# Read out of s2.<clinit>: bipush 19; newarray byte; bastore 0x51,0x75,0x6f,0x68,...
# Present identically in the app (classes3.dex, s2.<clinit> fill-array-data at
# 0x36a7f8 -> 51 75 6f 68 38 75 ...). Constant across 5.0.0 builds so far.
ADJ_VERIFICATION_XOR_KEY = bytes(
    [0x51, 0x75, 0x6F, 0x68, 0x38, 0x75, 0x61, 0x66, 0x6F, 0x68,
     0x67, 0x68, 0x37, 0x43, 0x61, 0x68, 0x4D, 0x32, 0x68]
)  # == b"Quoh8uafohgh7CahM2h"


def decode_adj_verification(value: str, key: bytes = ADJ_VERIFICATION_XOR_KEY) -> str:
    """
    Invert o3.a(): adj_verification = Base64.NO_WRAP( XOR(serialized_a0, s2.a) ).

    The plaintext is a serialized `a0` -- device/environment state collected at
    sign time (kotlinx-serialization-style encoder: n1/l1/v2/o1). It is the
    client-side integrity report, NOT a signature, and it is fully readable once
    you have this key. Feed it a real captured header to see what the SDK is
    reporting about the device.
    """
    import base64
    raw = base64.b64decode(value)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)).decode("utf-8", "replace")


# --------------------------------------------------------------------------------------
# Backends for the final (non-reproducible) step
# --------------------------------------------------------------------------------------

class SignatureBackend:
    """Returns the Base64 signature that goes in the header."""

    def sign(self, params, adj_signing_id: str, headers_id: str) -> str:  # pragma: no cover
        raise NotImplementedError


class LocalKeyBackend(SignatureBackend):
    """
    Full offline signing -- ONLY usable when you possess the raw HMAC key.

    That happens in exactly one situation: the API 18-22 software fallback in
    com.adjust.sdk.sig.c, where the key is 16 random bytes RSA-wrapped into
    SharedPreferences adjust_keys -> "encrypted_key". On API >= 23 (i.e. every
    real device today) key2 lives in the TEE and cannot be dumped.

    NOTE: this still does NOT reproduce nSign()'s 176-byte blob. It reproduces the
    *Java-side* HMAC, which is the input to nSign -- useful for cross-checking a
    device trace, not for minting an accepted signature on its own.
    """

    def __init__(self, raw_key: bytes, initial_capacity: int = 16):
        self.raw_key, self.initial_capacity = raw_key, initial_capacity

    def sign(self, params, adj_signing_id: str, headers_id: str) -> str:
        import base64

        msg = canonical_bytes(params, self.initial_capacity)
        return base64.b64encode(hmac_sha256(self.raw_key, msg)).decode()


class DeviceOracleBackend(SignatureBackend):
    """
    The backend that actually works: ask a real device.

    Subclass and implement `call_signer` with a frida RPC that invokes
    com.adjust.sdk.sig.Signer.sign(ctx, params, activityKind, clientSdk) inside the
    target app and returns the resulting signature. The keystore key never leaves
    the TEE, so this is the only way to mint server-accepted signatures.

    Expect the app's anti-tamper to fight you: libsigner.so ships a large
    emulator/Frida detector (TracerPid:, ro.kernel.qemu.*, /dev/qemu_pipe,
    Bluestacks/Nox/MEMU markers), and frida-server gets killed repeatedly.
    """

    def __init__(self, call_signer):
        self._call_signer = call_signer

    def sign(self, params, adj_signing_id: str, headers_id: str) -> str:
        return self._call_signer(params)


# --------------------------------------------------------------------------------------
# The field allow-list the native side filters to (decoded from libsigner.so, 5.0.0)
# --------------------------------------------------------------------------------------

SIGNED_FIELDS = """
ad_impressions_count ad_revenue_network ad_revenue_placement ad_revenue_unit
adj_verification adgroup adjust_product_id adjust_transaction_id android_id
android_uuid api_level app_secret app_token app_version app_version_short att_status
bundle_id callback_params campaign click_time click_time_server country created_at
creative currency deduplication_id default_tracker details device_known device_name
device_type environment event_callback_id event_count event_token external_device_id
fb_anon_id fb_id ff_app_set_id_disabled ff_att_disabled ff_idfv_disabled
ff_odm_enabled ff_remote_triggers_callback fire_adid fire_tracking_enabled
found_location google_play_instant gps_adid gps_adid_src
granular_third_party_sharing_options hardware_name idfa idfv initiated_by
initiating_package_name install_begin_time install_begin_time_server install_version
installed_at is_system_app is_updated_system_app last_skan_update mcc measurement
mnc needs_cost odm_info order_id originating_package_name os_build os_name os_version
package_name params partner_params partner_sharing_settings payload payloads
payment_backend primary_dedupe_token purchase_payload purchase_time push_token
referrer referrer_api reftag revenue sales_region secondary_dedupe_token secret_id
seq session_count session_length sharing skadn_registered_at snapshot_hash source
started_at store_app_id_from_client store_name_from_client store_name_from_system
subsession_count time_spent tracker tracking_enabled updated_at user_id
activity_kind client_sdk headers_id native_version
""".split()


if __name__ == "__main__":  # tiny smoke test
    demo = {"app_token": "abc123", "activity_kind": "session", "client_sdk": "android5.6.1"}
    print(canonical_string(demo, initial_capacity=16))
    print(canonical_string(demo, initial_capacity=64))
