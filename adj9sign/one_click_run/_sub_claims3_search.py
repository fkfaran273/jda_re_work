"""_sub_claims3_search.py — claims-cracking search with the REAL iOS-core
vocabulary (decoded from the closed AdjustSigSdk 5.0.0 arm64 binary,
_sub_core_diff_RESULT.md).

Oracle (validated): rec[46:78] == sha256_iv2(D9(20 zeros) || 00 08 || head16 ||
LE32(S) || sha256("") || 02 || device_field(16) || claims)   — via
_sub_ios_claims2_oracle.oracle_batch (Android-gold-validated 9/9).

NEW vocabulary keys and the buildable values tested here (never testable in
the previous ~67M-hypothesis stages):
  network_payload  raw urlencoded request body (POST) / query (GET);
                   also decoded-body and body+query forms
  authorization    the captured Authorization header minus the signature
                   field (buildable); also signature="" and full forms
  signature        "" / captured b64 (self-referential — cheap disproof)
  secret_id        absent / "" / constant-string candidates
  environment      production (wire) / sandbox (core literal) / capitalised
  os_name          ios (wire) / ios-simulator (core rewrite for sim builds)
Orders tested: Android sorted law (profile/pinned/tail/envelope), the binary's
weak hint order (signature,headers_id,adj_signing_id,native_version,algorithm)
as prefix/suffix, the dictionary-construction order, the device-claims cluster
order, the auth-header order, and raw wire-insertion order.
"""
import base64
import hashlib
import itertools
import json
import os
import re
import struct
import sys
import zipfile

from urllib.parse import urlsplit, unquote_to_bytes, unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_signer as sg
import numpy as np
from _sub_unseal_core import whiten_inverse
import _sub_ios_mint as mint
from _sub_ios_claims2_oracle import oracle_batch  # the VALIDATED harness
from _sub_ios_claims2_oracle import validate_on_android_golds

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"

ADJ_SIGNING_ID = "1500000"
CLIENT_SDK = "ios5.8.0"
HEADERS_ID = "10"
NATIVE_VERSION = "5.0.0"
ALGORITHM = "adj9"
SHA0 = hashlib.sha256(b"").digest()

# The captured adj_verification (== f("ios-simulator")) and the device form.
ADJV_CAP = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"
ADJV_IOS = mint.make_adj_verification("ios")

# iOS-name profile list: Android PROFILE with the iOS renames applied.
IOS_PROFILE_BASE = [
    'adj_verification', 'app_token', 'app_version', 'app_version_short',
    'att_status', 'attribution_deeplink', 'attribution_token', 'bundle_id',
    'created_at', 'device_name', 'device_type', 'environment',
    'enqueue_size', 'fb_anon_id', 'foreground', 'idfa', 'idfv',
    'installed_at', 'needs_response_details', 'offline_mode_enabled',
    'os_name', 'os_version', 'primary_dedupe_token', 'queue_size',
    'retry_count', 'send_in_background_enabled', 'sent_at', 'started_at',
]
CLICK_EXTRA = list(sg.CLICK_EXTRA)
SESSION_EXTRA = ['initiating_package_name']
SESSION_TAIL = ['session_count', 'session_length', 'store_name_from_system',
                'subsession_count', 'time_spent', 'tracking_enabled',
                'updated_at']
CLICK_TAIL = ['session_count', 'session_length', 'source',
              'subsession_count', 'time_spent', 'tracking_enabled',
              'updated_at']
ATTR_TAIL = ['tracking_enabled']
ATTR_DROP = ['hardware_name', 'installed_at', 'os_build']
EVENT_PROFILE_EXTRA = ['event_count', 'event_token', 'partner_params',
                       'callback_params', 'last_skan_update',
                       'skadn_registered_at', 'source']
EVENT_TAIL_EXTRA = ['seq']
BLOCK2 = ['activity_kind', 'client_sdk', 'headers_id', 'native_version']
# injected-only keys (values bound per record)
INJECTABLE = ['signature', 'authorization', 'network_payload', 'secret_id',
              'algorithm', 'adj_verification', 'os_name', 'environment']


# ----------------------------------------------------------------------
# corpus (extended loader, val parsing identical to the validated oracle)
# ----------------------------------------------------------------------
def load_corpus():
    z = zipfile.ZipFile(SAZ)
    out = []
    for name in sorted(z.namelist()):
        if not re.fullmatch(r"raw/\d+_c\.txt", name):
            continue
        txt = z.read(name).decode("latin1")
        m = re.search(r'signature="([A-Za-z0-9+/=]+)"', txt)
        if not m:
            continue
        blob = base64.b64decode(m.group(1))
        head, _, body = txt.partition("\r\n\r\n")
        host = re.search(r"^Host: ([^\r\n]+)", head, re.M).group(1)
        am = re.search(r"^Authorization: (.*)$", head, re.M)
        auth_full = am.group(1).rstrip("\r\n") if am else None
        p = urlsplit(head.split("\r\n")[0].split(" ")[1])
        path = p.path
        raw_query = p.query or ""
        val = {}
        for kv in (raw_query.split("&") if raw_query else []) + body.split("&"):
            k, _, v = kv.partition("=")
            k2 = unquote_plus(k)
            v2 = unquote_to_bytes(unquote_plus(v)).decode("latin1")
            if k2 in val and val[k2] != v2:
                raise ValueError("dup key %r" % k2)
            val[k2] = v2
        # decoded body in wire order (k=v& joined, values url-decoded)
        dec_body = "&".join(
            "%s=%s" % (unquote_plus(kv.partition("=")[0]),
                       unquote_to_bytes(unquote_plus(kv.partition("=")[2]))
                       .decode("latin1"))
            for kv in body.split("&") if kv)
        out.append({
            "file": os.path.basename(name),
            "kind": path.strip("/").replace("sdk_click", "click"),
            "host": host,
            "path": path,
            "val": val,
            "raw_body": body,
            "raw_query": raw_query,
            "dec_body": dec_body,
            "auth_full": auth_full,
            "sig_b64": m.group(1),
            "blob": blob,
            "rec": whiten_inverse(blob[16:160], blob[:16]),
        })
    for r in out:
        rec = r["rec"]
        r["S"] = int.from_bytes(rec[20:24], "big")
        r["head16"] = rec[3:19]
        r["block"] = rec[46:78]
        r["dev"] = rec[114:130]
    return out


# authorization variants (all buildable server-side unless noted)
def auth_variants(r):
    a = r["auth_full"]
    if a is None:
        return {}
    nosig = re.sub(r'signature="[^"]*",', "", a)          # field removed
    nosig_ns = nosig.replace("Signature ", "", 1)          # + no scheme
    emptysig = re.sub(r'signature="[^"]*"', 'signature=""', a, count=1)
    return {
        "full": a,             # self-referential (cheap disproof)
        "nosig": nosig,        # Signature adj_signing_id=... (buildable)
        "nosig_ns": nosig_ns,  # adj_signing_id=... (buildable)
        "emptysig": emptysig,  # signature="" (buildable)
    }


# ----------------------------------------------------------------------
# value binding -> claims pool
# ----------------------------------------------------------------------
ENV_VALUES = {"production": "production", "sandbox": "sandbox",
              "Production": "Production", "Sandbox": "Sandbox"}
NP_VALUES = ("body", "dec", "bodyquery", "query", "target")


def np_value(r, mode):
    if mode == "body":
        return r["raw_body"]
    if mode == "dec":
        return r["dec_body"]
    if mode == "bodyquery":
        return r["raw_body"] + r["raw_query"]
    if mode == "query":
        return r["raw_query"]
    if mode == "target":
        return r["path"] + ("?" + r["raw_query"] if r["raw_query"] else "")
    raise ValueError(mode)


def bind_values(r, opt):
    """opt: dict with keys os_name, env, np, np2, auth, sig, secret, endpoint,
    adjv.  Returns dict key->value of the injected keys (present ones only)."""
    inj = {}
    inj["os_name"] = "ios-simulator" if opt["os_name"] == "sim" else "ios"
    inj["environment"] = ENV_VALUES[opt["env"]]
    if opt.get("alg") == "adj9":
        inj["algorithm"] = "adj9"
    if opt["adjv"] == "cap":
        inj["adj_verification"] = ADJV_CAP
    elif opt["adjv"] == "ios":
        inj["adj_verification"] = ADJV_IOS
    if opt["np"] is not None:
        inj["network_payload"] = np_value(r, opt["np"])
    if opt.get("np2") is not None:
        inj["network_payload"] = np_value(r, opt["np2"])
    if opt["auth"] is not None:
        inj["authorization"] = auth_variants(r)[opt["auth"]]
    if opt["sig"] == "empty":
        inj["signature"] = ""
    elif opt["sig"] == "cap":
        inj["signature"] = r["sig_b64"]
    if opt["secret"] == "empty":
        inj["secret_id"] = ""
    elif opt["secret"] == "1500000":
        inj["secret_id"] = "1500000"
    elif opt["secret"] == "10":
        inj["secret_id"] = "10"
    elif opt["secret"] == "one":
        inj["secret_id"] = "1"
    if opt["endpoint"] == "base":
        inj["endpoint"] = "https://" + r["host"]
    elif opt["endpoint"] == "path":
        inj["endpoint"] = "https://" + r["host"] + r["path"]
    inj["client_sdk"] = CLIENT_SDK
    inj["activity_kind"] = r["kind"]
    return inj


DEF_OPT = dict(os_name="wire", env="production", np=None, np2=None, auth=None,
               sig=None, secret=None, endpoint="base", adjv="cap")


# ----------------------------------------------------------------------
# serialization laws
# ----------------------------------------------------------------------
def pool_of(r, opt):
    """The merged signing pool: wire params + injected values."""
    pool = {k: v for k, v in r["val"].items() if k != ""}
    pool.update(bind_values(r, opt))
    for k in (opt.get("drop") or []):
        pool.pop(k, None)
    return pool


def profile_tail_keys(kind):
    if kind == "session":
        prof = IOS_PROFILE_BASE + SESSION_EXTRA
        tail = SESSION_TAIL
    elif kind == "click":
        prof = IOS_PROFILE_BASE + CLICK_EXTRA + ['last_skan_update',
                                                 'skadn_registered_at']
        tail = CLICK_TAIL
    elif kind == "attribution":
        prof = [k for k in IOS_PROFILE_BASE if k not in ATTR_DROP] \
            + ['initiated_by', 'last_skan_update', 'skadn_registered_at']
        tail = ATTR_TAIL
    elif kind == "event":
        prof = IOS_PROFILE_BASE + EVENT_PROFILE_EXTRA
        tail = SESSION_TAIL + EVENT_TAIL_EXTRA
    else:
        raise ValueError(kind)
    return prof, tail


def envelope_str(kind):
    return (kind + CLIENT_SDK + HEADERS_ID + NATIVE_VERSION)


def law_sorted_split(r, opt, envelope=True, pinned_mid=True,
                     inject_in="profile"):
    """Android-style law over the iOS vocabulary: sorted profile values,
    pinned 1500000, sorted tail values, envelope (activity_kind, client_sdk,
    headers_id, native_version)."""
    pool = pool_of(r, opt)
    prof, tail = profile_tail_keys(r["kind"])
    prof = [k for k in prof if k not in INJECTABLE]
    tail = [k for k in tail if k not in INJECTABLE]
    inj_keys = [k for k in INJECTABLE if k in pool and k != "adj_signing_id"]
    if inject_in == "profile":
        prof = prof + inj_keys
    elif inject_in == "tail":
        tail = tail + inj_keys
    parts = []
    for k in sorted(prof):
        v = pool.get(k)
        if v is not None and v != "":
            parts.append(v)
        elif v == "":
            parts.append(v)          # present-but-empty still emits ""
    if pinned_mid:
        parts.append(ADJ_SIGNING_ID)
    for k in sorted(tail):
        v = pool.get(k)
        if v:
            parts.append(v)
    if not pinned_mid:
        parts.append(ADJ_SIGNING_ID)
    if envelope:
        parts.append(envelope_str(r["kind"]))
    return "".join(parts).encode("latin1")


def law_sorted_one(r, opt, envelope=True):
    """Single alphabetical run over the whole pool, pinned in sort position."""
    pool = pool_of(r, opt)
    pool = dict(pool)
    pool.pop("adj_signing_id", None)
    pool.pop("activity_kind", None)
    pool.pop("client_sdk", None)
    parts = []
    pinned_done = False
    for k in sorted(pool):
        if not pinned_done and k > "adj_signing_id":
            parts.append(ADJ_SIGNING_ID)
            pinned_done = True
        v = pool[k]
        if v is not None:
            parts.append(v)
    if not pinned_done:
        parts.append(ADJ_SIGNING_ID)
    if envelope:
        parts.append(envelope_str(r["kind"]))
    return "".join(parts).encode("latin1")


def law_wire_order(r, opt, envelope=True, inj_pos="end"):
    """Values in wire-insertion order (query then body), injected keys at
    end / front, then envelope."""
    pool = pool_of(r, opt)
    inj = bind_values(r, opt)
    wire_keys = [k for k in r["val"] if k not in inj or inj[k] == r["val"][k]]
    parts = []
    if inj_pos == "front":
        for k in inj:
            v = inj[k]
            if v is not None and (v != "" or k in ("signature", "secret_id")):
                parts.append(v)
    for k in wire_keys:
        v = r["val"].get(k)
        if v:
            parts.append(v)
    if inj_pos == "end":
        for k in inj:
            v = inj[k]
            if v is not None and (v != "" or k in ("signature", "secret_id")):
                parts.append(v)
    parts.append(ADJ_SIGNING_ID)
    if envelope:
        parts.append(envelope_str(r["kind"]))
    return "".join(parts).encode("latin1")


HINT5 = ["signature", "headers_id", "adj_signing_id", "native_version",
         "algorithm"]
DICT6 = ["adj_signing_id", "signature", "headers_id", "native_version",
         "algorithm", "adj_verification"]
CLUSTER = ["bundle_id", "idfv", "app_version", "app_version_short",
           "os_name", "adj_verification"]
AUTHHDR6 = ["signature", "adj_signing_id", "algorithm", "headers_id",
            "native_version", "adj_verification"]


def _fixed_vals(r, opt, keys):
    pool = pool_of(r, opt)
    out = []
    for k in keys:
        if k == "adj_signing_id":
            out.append(ADJ_SIGNING_ID)
        elif k == "headers_id":
            out.append(HEADERS_ID)
        elif k == "native_version":
            out.append(NATIVE_VERSION)
        elif k == "algorithm":
            out.append(ALGORITHM)
        elif k == "activity_kind":
            out.append(r["kind"])
        elif k == "client_sdk":
            out.append(CLIENT_SDK)
        else:
            v = pool.get(k)
            out.append(v if v is not None else "")
    return out


def law_order_prefix(r, opt, keys, rest="sorted_split", envelope=True):
    fixed = "".join(_fixed_vals(r, opt, keys))
    if rest == "sorted_split":
        rest_b = law_sorted_split(r, opt, envelope=False)
    elif rest == "sorted_one":
        rest_b = law_sorted_one(r, opt, envelope=False)
    elif rest == "wire":
        rest_b = law_wire_order(r, opt, envelope=False)
    else:
        raise ValueError(rest)
    tail = envelope_str(r["kind"]) if envelope else ""
    return (fixed + rest_b.decode("latin1") + tail).encode("latin1")


def law_order_suffix(r, opt, keys, rest="sorted_split", envelope=True):
    fixed = "".join(_fixed_vals(r, opt, keys))
    if rest == "sorted_split":
        rest_b = law_sorted_split(r, opt, envelope=False)
    elif rest == "sorted_one":
        rest_b = law_sorted_one(r, opt, envelope=False)
    elif rest == "wire":
        rest_b = law_wire_order(r, opt, envelope=False)
    else:
        raise ValueError(rest)
    tail = envelope_str(r["kind"]) if envelope else ""
    return (rest_b.decode("latin1") + tail + fixed).encode("latin1")


def law_vocab_only(r, opt, order="cluster", envelope=True):
    """Claims built ONLY from the core vocabulary keys (no other wire
    params) — the device-claims cluster + envelope + new keys."""
    pool = pool_of(r, opt)
    vocab = ["bundle_id", "idfv", "app_version", "app_version_short",
             "os_name", "environment", "adj_verification", "signature",
             "authorization", "network_payload", "secret_id", "algorithm"]
    present = {k: pool[k] for k in vocab if k in pool}
    parts = []
    if order == "cluster":
        seq = [k for k in CLUSTER[:-1]] + ["adj_verification"]
        for k in seq:
            if k in present:
                parts.append(present[k])
        for k in sorted(present):
            if k not in seq:
                parts.append(present[k])
    elif order == "sorted":
        for k in sorted(present):
            parts.append(present[k])
    elif order == "sorted_split":
        # injected non-vocab-envelope keys first sorted, then cluster
        for k in sorted(present):
            if k not in CLUSTER and k != "adj_verification":
                parts.append(present[k])
        for k in CLUSTER:
            if k in present:
                parts.append(present[k])
    if envelope:
        parts.append(envelope_str(r["kind"]))
    return "".join(parts).encode("latin1")


LAWS = {
    "sorted_split": law_sorted_split,
    "sorted_one": law_sorted_one,
    "wire_order_end": lambda r, o: law_wire_order(r, o, inj_pos="end"),
    "wire_order_front": lambda r, o: law_wire_order(r, o, inj_pos="front"),
    "hint5_prefix": lambda r, o: law_order_prefix(r, o, HINT5),
    "hint5_suffix": lambda r, o: law_order_suffix(r, o, HINT5),
    "dict6_prefix": lambda r, o: law_order_prefix(r, o, DICT6),
    "dict6_suffix": lambda r, o: law_order_suffix(r, o, DICT6),
    "cluster_prefix": lambda r, o: law_order_prefix(r, o, CLUSTER),
    "cluster_suffix": lambda r, o: law_order_suffix(r, o, CLUSTER),
    "authhdr6_prefix": lambda r, o: law_order_prefix(r, o, AUTHHDR6),
    "authhdr6_suffix": lambda r, o: law_order_suffix(r, o, AUTHHDR6),
    "vocab_cluster": lambda r, o: law_vocab_only(r, o, "cluster"),
    "vocab_sorted": lambda r, o: law_vocab_only(r, o, "sorted"),
    "vocab_sorted_split": lambda r, o: law_vocab_only(r, o, "sorted_split"),
}


# ----------------------------------------------------------------------
# stages
# ----------------------------------------------------------------------
RESULTS = {"stages": {}, "hits": []}
CHUNK = 20000


def run_stage(name, records, opts, law_names, note="", on_hit=None):
    """opts: list of opt dicts; law_names: names into LAWS."""
    n = 0
    hits = []
    for r in records:
        claims_list = []
        meta = []
        for opt in opts:
            for ln in law_names:
                claims_list.append(LAWS[ln](r, opt))
                meta.append((ln, json.dumps(opt, sort_keys=True)))
        for i0 in range(0, len(claims_list), CHUNK):
            chunk = claims_list[i0:i0 + CHUNK]
            arr = np.array(oracle_batch(r, chunk))
            n += len(chunk)
            idx = np.nonzero(arr)[0]
            for i in idx:
                gi = i0 + int(i)
                h = {"file": r["file"], "kind": r["kind"],
                     "law": meta[gi][0], "opt": meta[gi][1],
                     "claims": chunk[i].decode("latin1", "replace")}
                hits.append(h)
                RESULTS["hits"].append(h)
                print("  *** HIT:", h, flush=True)
                if on_hit:
                    on_hit(h)
    RESULTS["stages"][name] = {"n": n, "hits": hits, "note": note}
    print("[stage %s] %d candidates, %d hits" % (name, n, len(hits)),
          flush=True)
    with open(os.path.join(HERE, "_sub_claims3_out.json"), "w") as f:
        json.dump(RESULTS, f, indent=1)
    return hits


def base_opts(**kw):
    o = dict(DEF_OPT)
    o.update(kw)
    return o


def main():
    ok, n = validate_on_android_golds()
    print("oracle validation on android golds: %d/%d" % (ok, n), flush=True)
    if ok != n:
        print("ORACLE BROKEN — aborting", flush=True)
        sys.exit(1)
    corpus = load_corpus()
    print("corpus: %d signed requests" % len(corpus), flush=True)
    by_kind = {}
    for r in corpus:
        by_kind.setdefault(r["kind"], []).append(r)
    print("kinds:", {k: len(v) for k, v in by_kind.items()}, flush=True)
    reps = [by_kind[k][0] for k in ("session", "click", "attribution", "event")]
    print("representatives:", [r["file"] for r in reps], flush=True)

    # ---------------- stage 1: fixed laws, new values ----------------
    opts1 = []
    for np_m in (None, "body", "dec"):
        for auth in (None, "nosig", "emptysig", "nosig_ns"):
            for osn in ("wire", "sim"):
                opts1.append(base_opts(np=np_m, auth=auth, os_name=osn))
    hits1 = run_stage("1_fixed_laws", corpus, opts1,
                      ["sorted_split", "sorted_one", "wire_order_end"],
                      note="np x auth x os_name x 3 orders, all 30 records")

    # ---------------- stage 2: hint/dict/cluster/authhdr orders -------
    opts2 = [base_opts(np="body", auth="nosig"),
             base_opts(np="body", auth="nosig", os_name="sim"),
             base_opts(np=None, auth="nosig"),
             base_opts(np="body", auth=None),
             base_opts(np=None, auth=None, os_name="sim"),
             base_opts(np="dec", auth="nosig"),
             base_opts(np="body", auth="emptysig"),
             base_opts(np="body", auth="nosig", secret="empty"),
             base_opts(np="body", auth="nosig", sig="empty"),
             base_opts(np="body", auth="nosig", env="sandbox"),
             base_opts(np="bodyquery", auth="nosig"),
             base_opts(np="target", auth="nosig"),
             base_opts(np="query", auth="nosig"),
             base_opts(np="body", auth="full"),
             base_opts(np="body", auth="nosig", sig="cap"),
             base_opts(np="body", auth="nosig", secret="1500000"),
             base_opts(np="body", auth="nosig", secret="10"),
             base_opts(np="body", auth="nosig", secret="one"),
             base_opts(np="body", auth="nosig", endpoint="path"),
             base_opts(np="body", auth="nosig", adjv="ios")]
    law2 = ["hint5_prefix", "hint5_suffix", "dict6_prefix", "dict6_suffix",
            "cluster_prefix", "cluster_suffix", "authhdr6_prefix",
            "authhdr6_suffix", "wire_order_front"]
    hits2 = run_stage("2_orders", corpus, opts2, law2,
                      note="new-key bindings x 9 orders, all 30 records")

    # ---------------- stage 3: vocab-only laws ------------------------
    opts3 = []
    for np_m in (None, "body"):
        for auth in (None, "nosig"):
            for osn in ("wire", "sim"):
                opts3.append(base_opts(np=np_m, auth=auth, os_name=osn))
    hits3 = run_stage("3_vocab_only", corpus, opts3,
                      ["vocab_cluster", "vocab_sorted",
                       "vocab_sorted_split"],
                      note="core-vocabulary-only claims, 3 orders")

    # ---------------- stage 4: full combinatorial on injected keys ----
    opts4 = []
    for np_m in (None, "body", "dec", "bodyquery", "target", "query"):
        for auth in (None, "nosig", "emptysig", "nosig_ns", "full"):
            for sig in (None, "empty", "cap"):
                for env in ("production", "sandbox", "Production",
                            "Sandbox"):
                    for osn in ("wire", "sim"):
                        for secret in (None, "empty", "1500000", "10",
                                       "one"):
                            for endpoint in ("base", "path"):
                                opts4.append(base_opts(
                                    np=np_m, auth=auth, sig=sig, env=env,
                                    os_name=osn, secret=secret,
                                    endpoint=endpoint))
    law4 = ["sorted_split", "sorted_one", "wire_order_end",
            "hint5_prefix", "hint5_suffix", "dict6_prefix", "dict6_suffix",
            "cluster_prefix", "cluster_suffix", "authhdr6_prefix",
            "authhdr6_suffix", "wire_order_front", "vocab_cluster",
            "vocab_sorted", "vocab_sorted_split"]
    hits4 = run_stage("4_combinatorial_reps", reps, opts4, law4,
                      note="full injected-key cross product x 15 laws, "
                           "4 representative records")

    total = sum(s["n"] for s in RESULTS["stages"].values())
    print("TOTAL: %d candidates, %d hits" % (total, len(RESULTS["hits"])),
          flush=True)
    with open(os.path.join(HERE, "_sub_claims3_out.json"), "w") as f:
        json.dump(RESULTS, f, indent=1)
    return RESULTS


if __name__ == "__main__":
    main()
