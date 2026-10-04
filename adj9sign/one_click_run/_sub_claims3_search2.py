"""_sub_claims3_search2.py — claims3 stage 5+: corrected full key lists
(started_at/queue_size/attribution_token present), membership toggles,
envelope/pinned variants, canonical-name law, serializations, np hashes,
injected-only laws, JSON forms.  Reuses the validated oracle + search1 laws.
"""
import hashlib
import itertools
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _sub_claims3_search as S1
from _sub_ios_claims2_oracle import oracle_batch

RESULTS = {"stages": {}, "hits": []}
CHUNK = 20000

UNCERTAIN = ["started_at", "queue_size", "attribution_token",
             "last_skan_update", "skadn_registered_at", "callback_params",
             "source", "event_count", "event_token", "seq"]

LAWS5 = dict(S1.LAWS)


# ---------------- new laws -------------------------------------------------
def env_variants(kind, opt):
    std = kind + S1.CLIENT_SDK + S1.HEADERS_ID + S1.NATIVE_VERSION
    out = {"std": std,
           "alg": std + S1.ALGORITHM,
           "pinned": std + S1.ADJ_SIGNING_ID,
           "adjv": std + S1.ADJV_CAP,
           "none": "",
           "first": ""}
    return out


def law_env(r, opt, envmode, pinned="mid"):
    """sorted_split with an envelope variant / pinned placement."""
    pool = S1.pool_of(r, opt)
    prof, tail = S1.profile_tail_keys(r["kind"])
    prof = [k for k in prof if k not in S1.INJECTABLE]
    tail = [k for k in tail if k not in S1.INJECTABLE]
    inj_keys = [k for k in S1.INJECTABLE if k in pool]
    prof = prof + inj_keys
    parts = [pool.get(k, "") or "" for k in sorted(prof)]
    if pinned == "first":
        parts.insert(0, S1.ADJ_SIGNING_ID)
    elif pinned in ("mid", "last"):
        parts.append(S1.ADJ_SIGNING_ID)
    for k in sorted(tail):
        v = pool.get(k)
        if v:
            parts.append(v)
    if pinned == "last" and False:
        pass
    env = env_variants(r["kind"], opt)[envmode]
    if envmode == "first":
        return (env + "".join(parts)).encode("latin1")
    return ("".join(parts) + env).encode("latin1")


for _em in ("std", "alg", "pinned", "adjv", "none", "first"):
    for _pm in ("mid", "first", "last"):
        LAWS5["env_%s_pin_%s" % (_em, _pm)] = (
            lambda r, o, _em=_em, _pm=_pm: law_env(r, o, _em, _pm))


def law_canonical(r, opt, mode="split"):
    """Android-canonical names: package_name<-bundle_id, android_uuid<-idfv,
    gps_adid<-idfa (+gps_adid_src absent) — with the new injected keys."""
    pool = S1.pool_of(r, opt)
    pool = dict(pool)
    ren = {"bundle_id": "package_name", "idfv": "android_uuid",
           "idfa": "gps_adid"}
    for old, new in ren.items():
        if old in pool:
            pool[new] = pool.pop(old)
    prof, tail = S1.profile_tail_keys(r["kind"])
    prof = [ren.get(k, k) for k in prof]
    tail = [ren.get(k, k) for k in tail]
    prof = [k for k in prof if k not in S1.INJECTABLE]
    tail = [k for k in tail if k not in S1.INJECTABLE]
    inj_keys = [k for k in S1.INJECTABLE if k in pool]
    if mode == "split":
        prof = prof + inj_keys
        parts = [pool.get(k, "") or "" for k in sorted(prof)]
        parts.append(S1.ADJ_SIGNING_ID)
        parts += [pool.get(k, "") or "" for k in sorted(tail) if pool.get(k)]
    else:
        prof = prof + inj_keys + tail
        parts = [pool.get(k, "") or "" for k in sorted(prof)]
        parts.append(S1.ADJ_SIGNING_ID)
    parts.append(r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID
                 + S1.NATIVE_VERSION)
    return "".join(parts).encode("latin1")


LAWS5["canonical_split"] = law_canonical
LAWS5["canonical_one"] = lambda r, o: law_canonical(r, o, "one")


def _ser_pool(r, opt):
    pool = S1.pool_of(r, opt)
    pool.pop("adj_signing_id", None)
    return pool


def law_kv(r, opt, sep="=", join="&", order="sorted", envelope=True,
           lencode=0):
    pool = _ser_pool(r, opt)
    keys = sorted(pool) if order == "sorted" else list(pool)
    parts = []
    for k in keys:
        v = pool[k]
        if lencode == 2:
            parts.append("%02x%s%s%s" % (len(v), sep, k, sep)
                         if False else
                         chr(len(v)) + k + sep + v)
        elif lencode == 4:
            parts.append(k + sep + v)
        else:
            parts.append("%s%s%s" % (k, sep, v))
    mid = join.join(parts)
    if lencode == 4:
        mid = "".join(struct_pack4(k + sep + pool[k]) for k in keys)
    tail = (r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID + S1.NATIVE_VERSION
            if envelope else "")
    pinned = S1.ADJ_SIGNING_ID
    return (pinned + mid + tail).encode("latin1")


def struct_pack4(s):
    import struct as _s
    b = s.encode("latin1")
    return _s.pack(">I", len(b)) + b


def law_valjoin(r, opt, join="&", order="sorted", envelope=True):
    pool = _ser_pool(r, opt)
    keys = sorted(pool) if order == "sorted" else list(pool)
    mid = join.join(pool[k] for k in keys)
    tail = (r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID + S1.NATIVE_VERSION
            if envelope else "")
    return (S1.ADJ_SIGNING_ID + mid + tail).encode("latin1")


def law_lenprefixed(r, opt, size=4, order="sorted", envelope=True):
    pool = _ser_pool(r, opt)
    keys = sorted(pool) if order == "sorted" else list(pool)
    import struct as st
    parts = []
    for k in keys:
        b = (k + "=" + pool[k]).encode("latin1")
        parts.append((st.pack(">H", len(b)) if size == 2
                      else st.pack(">I", len(b))) + b)
    tail = (r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID + S1.NATIVE_VERSION
            if envelope else "")
    return (S1.ADJ_SIGNING_ID + "".join(x.decode("latin1") for x in parts)
            + tail).encode("latin1")


LAWS5["kv_amp_sorted"] = lambda r, o: law_kv(r, o, "&")
LAWS5["kv_semi_sorted"] = lambda r, o: law_kv(r, o, ";")
LAWS5["kv_colon_sorted"] = lambda r, o: law_kv(r, o, ":", join="")
LAWS5["kv_amp_wire"] = lambda r, o: law_kv(r, o, "&", order="wire")
LAWS5["val_amp"] = lambda r, o: law_valjoin(r, o, "&")
LAWS5["val_nl"] = lambda r, o: law_valjoin(r, o, "\n")
LAWS5["len4_sorted"] = lambda r, o: law_lenprefixed(r, o, 4)
LAWS5["len2_sorted"] = lambda r, o: law_lenprefixed(r, o, 2)


def law_np_hash(r, opt, h="sha256hex", case="lower"):
    body = r["raw_body"].encode("latin1")
    if h == "sha256hex":
        v = hashlib.sha256(body).hexdigest()
    elif h == "sha256b64":
        import base64
        v = base64.b64encode(hashlib.sha256(body).digest()).decode()
    elif h == "sha1hex":
        v = hashlib.sha1(body).hexdigest()
    elif h == "md5hex":
        v = hashlib.md5(body).hexdigest()
    if case == "upper":
        v = v.upper()
    opt = dict(opt)
    opt["np2"] = None
    pool = S1.pool_of(r, opt)
    pool["network_payload"] = v
    prof, tail = S1.profile_tail_keys(r["kind"])
    prof = [k for k in prof if k not in S1.INJECTABLE]
    tail = [k for k in tail if k not in S1.INJECTABLE]
    inj_keys = [k for k in S1.INJECTABLE if k in pool and k != "network_payload"]
    prof = prof + inj_keys + ["network_payload"]
    parts = [pool.get(k, "") or "" for k in sorted(prof)]
    parts.append(S1.ADJ_SIGNING_ID)
    parts += [pool.get(k, "") or "" for k in sorted(tail) if pool.get(k)]
    parts.append(r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID
                 + S1.NATIVE_VERSION)
    return "".join(parts).encode("latin1")


for _h in ("sha256hex", "sha256b64", "sha1hex", "md5hex"):
    LAWS5["np_hash_" + _h] = (lambda _h: (lambda r, o: law_np_hash(r, o, _h)))(_h)
LAWS5["np_hash_sha256HEX"] = lambda r, o: law_np_hash(r, o, "sha256hex",
                                                      "upper")


def law_inj_only(r, opt, order="sorted", envelope=True):
    pool = S1.pool_of(r, opt)
    inj = {k: pool[k] for k in S1.INJECTABLE if k in pool}
    inj["endpoint"] = pool.get("endpoint", "")
    inj["client_sdk"] = S1.CLIENT_SDK
    inj["activity_kind"] = r["kind"]
    keys = sorted(inj) if order == "sorted" else list(inj)
    parts = [inj[k] or "" for k in keys]
    parts.append(S1.ADJ_SIGNING_ID)
    if envelope:
        parts.append(r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID
                     + S1.NATIVE_VERSION)
    return "".join(parts).encode("latin1")


LAWS5["inj_sorted"] = law_inj_only
LAWS5["inj_dict"] = lambda r, o: law_inj_only(r, o, "dict")


def law_auth_only(r, opt, envelope=True):
    av = S1.auth_variants(r)
    v = av.get(opt["auth"], "")
    tail = (r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID + S1.NATIVE_VERSION
            if envelope else "")
    return (v + tail).encode("latin1")


def law_np_only(r, opt, envelope=True):
    v = S1.np_value(r, opt["np"]) if opt["np"] else ""
    tail = (r["kind"] + S1.CLIENT_SDK + S1.HEADERS_ID + S1.NATIVE_VERSION
            if envelope else "")
    return (v + tail).encode("latin1")


def law_json(r, opt, sorted_keys=True, values=False):
    pool = _ser_pool(r, opt)
    pool["adj_signing_id"] = S1.ADJ_SIGNING_ID
    pool["activity_kind"] = r["kind"]
    pool["client_sdk"] = S1.CLIENT_SDK
    if values:
        keys = sorted(pool) if sorted_keys else list(pool)
        s = json.dumps([pool[k] for k in keys], separators=(",", ":"))
    else:
        s = json.dumps(pool, separators=(",", ":"),
                       sort_keys=sorted_keys)
    return s.encode("latin1")


LAWS5["auth_only"] = law_auth_only
LAWS5["np_only"] = law_np_only
LAWS5["json_compact"] = law_json
LAWS5["json_values"] = lambda r, o: law_json(r, o, values=True)


# ---------------- runner ---------------------------------------------------
def run_stage(name, records, opts, law_names, note="", on_hit=None):
    n = 0
    hits = []
    for r in records:
        claims_list = []
        meta = []
        for opt in opts:
            for ln in law_names:
                claims_list.append(LAWS5[ln](r, opt))
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


def bo(**kw):
    return S1.base_opts(**kw)


def main():
    ok, n = S1.validate_on_android_golds()
    print("oracle validation on android golds: %d/%d" % (ok, n), flush=True)
    corpus = S1.load_corpus()
    by_kind = {}
    for r in corpus:
        by_kind.setdefault(r["kind"], []).append(r)
    reps = [by_kind[k][0] for k in ("session", "click", "attribution", "event")]

    # 5a: corrected full lists x new bindings x 14 laws, all 30 records
    opts5a = [bo(np=np_m, auth=au, os_name=osn, adjv=av, alg=alg)
              for np_m in (None, "body", "dec")
              for au in ("nosig", "emptysig", "nosig_ns")
              for osn in ("wire", "sim")
              for av in ("cap", "ios")
              for alg in (None, "adj9")]
    run_stage("5a_full_lists", corpus, opts5a,
              ["sorted_split", "sorted_one", "wire_order_end",
               "wire_order_front", "hint5_prefix", "hint5_suffix",
               "dict6_prefix", "dict6_suffix", "cluster_prefix",
               "cluster_suffix", "authhdr6_prefix", "authhdr6_suffix",
               "vocab_cluster", "vocab_sorted_split"],
              note="corrected full wire lists (started_at/queue_size/"
                   "attribution_token present) x np x auth x os x adjv x alg")

    # 5b: membership toggles over uncertain keys, reps
    opts5b = []
    base = bo(np="body", auth="nosig")
    for mask in range(64):
        opt = dict(base)
        opt["drop"] = [k for i, k in enumerate(
            ["started_at", "queue_size", "attribution_token",
             "last_skan_update", "skadn_registered_at", "callback_params"])
            if mask >> i & 1]
        opts5b.append(opt)
    # apply drops via a pool wrapper law
    orig_laws = {k: LAWS5[k] for k in ("sorted_split", "sorted_one",
                                       "hint5_prefix", "dict6_prefix",
                                       "authhdr6_prefix")}

    def with_drops(fn):
        def g(r, opt):
            drops = opt.get("drop") or []
            if not drops:
                return fn(r, opt)
            saved = {k: r["val"][k] for k in drops if k in r["val"]}
            for k in drops:
                r["val"].pop(k, None)
            try:
                return fn(r, opt)
            finally:
                r["val"].update(saved)
        return g
    for k, fn in orig_laws.items():
        LAWS5["d_" + k] = with_drops(fn)
    run_stage("5b_membership", reps, opts5b,
              ["d_sorted_split", "d_sorted_one", "d_hint5_prefix",
               "d_dict6_prefix", "d_authhdr6_prefix"],
              note="2^6 membership drops of uncertain wire keys x 5 laws, "
                   "4 representative records")

    # 5c: envelope x pinned variants, reps
    opts5c = [bo(np="body", auth="nosig"),
              bo(np="body", auth="nosig", os_name="sim"),
              bo(np=None, auth="nosig")]
    laws5c = ["env_%s_pin_%s" % (e, p) for e in ("std", "alg", "pinned",
                                                 "adjv", "none", "first")
              for p in ("mid", "first", "last")]
    run_stage("5c_envelope_pinned", reps, opts5c, laws5c,
              note="envelope x pinned placements x 3 bindings, 4 reps")

    # 5d: canonical-name law, all 30
    opts5d = [bo(np=np_m, auth=au, os_name=osn)
              for np_m in (None, "body")
              for au in ("nosig", "emptysig")
              for osn in ("wire", "sim")]
    run_stage("5d_canonical", corpus, opts5d,
              ["canonical_split", "canonical_one"],
              note="android-canonical names (package_name/android_uuid/"
                   "gps_adid) x new keys, all 30")

    # 5e: serializations, reps
    opts5e = [bo(np="body", auth="nosig"), bo(np=None, auth="nosig"),
              bo(np="dec", auth="nosig")]
    run_stage("5e_serializations", reps, opts5e,
              ["kv_amp_sorted", "kv_semi_sorted", "kv_colon_sorted",
               "kv_amp_wire", "val_amp", "val_nl", "len4_sorted",
               "len2_sorted"],
              note="k=v / joined / length-prefixed serializations with new "
                   "keys, 4 reps")

    # 5f: network_payload hash forms, all 30
    opts5f = [bo(auth="nosig", os_name="sim"), bo(auth="nosig")]
    run_stage("5f_np_hash", corpus, opts5f,
              ["np_hash_sha256hex", "np_hash_sha256HEX", "np_hash_sha256b64",
               "np_hash_sha1hex", "np_hash_md5hex"],
              note="network_payload = sha256/sha1/md5 of raw body")

    # 5g: injected-only laws, all 30
    run_stage("5g_inj_only", corpus, opts5f,
              ["inj_sorted", "inj_dict", "auth_only", "np_only"],
              note="injected-keys-only / auth-only / np-only claims")

    # 5h: JSON forms with new keys, all 30
    run_stage("5h_json", corpus, opts5f, ["json_compact", "json_values"],
              note="compact/sorted JSON dict and values-array incl. "
                   "injected keys")

    total = sum(s["n"] for s in RESULTS["stages"].values())
    print("TOTAL stage5+: %d candidates, %d hits"
          % (total, len(RESULTS["hits"])), flush=True)
    with open(os.path.join(HERE, "_sub_claims3_out.json"), "w") as f:
        json.dump(RESULTS, f, indent=1)


if __name__ == "__main__":
    main()
