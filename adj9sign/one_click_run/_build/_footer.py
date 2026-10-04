# =======================================================================
# PART 8 — THE ONE-CLICK API: configure() one app, then sign() requests.
# =======================================================================

_cfg = {}
DESC9 = None                             # descriptor #9 — set by configure()
ADJ_SIGNING_ID = "1500000"               # pinned claim + header value
ADJ_VERIFICATION = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
CLIENT_SDK = "android5.7.0"              # Client-SDK header + claims client_sdk
NATIVE_VERSION = "5.0.0"
HEADERS_ID = "10"


def configure(campaign_data):
    """Patch the per-app constants from campaign_data (one app).  The only
    REQUIRED key is cert_sha1; the rest have safe defaults.  Call once
    before any sign()."""
    global _cfg, DESC9, ADJ_SIGNING_ID, ADJ_VERIFICATION, NATIVE_VERSION
    global CLIENT_SDK, HEADERS_ID
    _cfg = dict(campaign_data)
    if _cfg.get("algorithm", "adj9") != "adj9":
        print("[SIGNER] WARNING: algorithm=%r is not adj9"
              % _cfg.get("algorithm"), flush=True)
    DESC9 = bytes.fromhex(_cfg["cert_sha1"])
    ADJ_SIGNING_ID = str(_cfg.get("adj_signing_id", ADJ_SIGNING_ID))
    ADJ_VERIFICATION = str(_cfg.get("adj_verification", ADJ_VERIFICATION))
    NATIVE_VERSION = str(_cfg.get("native_version", NATIVE_VERSION))
    CLIENT_SDK = str(_cfg.get("client_sdk", CLIENT_SDK))
    HEADERS_ID = str(_cfg.get("headers_id", HEADERS_ID))
    return _cfg


def _parse_head(v):
    """head_phase config string ("2b" / "2b,48") -> tuple."""
    if isinstance(v, str):
        return tuple(int(x, 16) for x in v.replace(":", ",").split(",")
                     if x.strip())
    return tuple(v)


def sign_request(params, kind, head=None, second=None, seed=None):
    """One fresh signing: own clock second, own seed S, own claims.

    params : the request's wire fields as a dict (device data / click fields)
    kind   : "session" | "click" | "attribution"
    head   : the d0 selector phase, or None -> a fresh random selector.
             The phase is provably a free value: the server cannot verify
             it (live-verified with a non-pool value, funnel_random_phase).
    returns (blob_192B, second, info)
    """
    if DESC9 is None:
        raise RuntimeError("call configure(campaign_data) first "
                           "(it sets cert_sha1)")
    if head is None:
        head = (os.urandom(1)[0] % 127,)   # fresh selector 0..126:
        # keeps the expansion mask (s<<1)+3 inside 8 bits, the domain
        # the native's selector formula operates in (pool max 72)
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": CLIENT_SDK,
                "adj_signing_id": ADJ_SIGNING_ID, "headers_id": HEADERS_ID,
                "native_version": NATIVE_VERSION,
                "adj_verification": ADJ_VERIFICATION})
    second = int(second if second is not None else time.time())
    seed = int.from_bytes(os.urandom(4), "big") if seed is None else int(seed)
    cb = build_claims(val, kind)
    blob = sign_pure(second, seed, cb, d9_hex=DESC9.hex(),
                     kind=kind, head=head)
    info = {"S": seed, "kind": kind, "claims_len": len(cb), "head": head,
            "second": second}
    return blob, second, info


def sign(params, kind, head=None, second=None, seed=None):
    """sign_request with configure()'s head_phase override (explicit head
    still wins; None -> random phase).  returns (blob, second, info). ~3 ms."""
    if head is None and _cfg.get("head_phase"):
        head = _parse_head(_cfg["head_phase"])
    return sign_request(params, kind, head=head, second=second, seed=seed)


def auth_header(blob):
    """The Authorization header value for a minted blob."""
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_SIGNING_ID, HEADERS_ID,
               NATIVE_VERSION, ADJ_VERIFICATION))


def api_host():
    """The Adjust API host for this app's requests."""
    return _cfg.get("api_host", "app.adjust.com")


def client_sdk():
    """The Client-SDK header value for every request."""
    return CLIENT_SDK


def status():
    """A human-readable config summary (for the funnel's startup print)."""
    cert = _cfg.get("cert_sha1", "?")
    return ("[SIGNER] app            : %s\n"
            "[SIGNER] cert_sha1      : %s... (%d B)\n"
            "[SIGNER] adj_signing_id : %s   headers_id: %s\n"
            "[SIGNER] client_sdk     : %s   (Client-SDK header + claim)\n"
            "[SIGNER] native_version : %s   adj_verification: %s\n"
            "[SIGNER] head_phase     : %s   api_host: %s\n"
            "[SIGNER] engine         : closed-form algorithm, ~3 ms/signing"
            % (_cfg.get("package_name", "?"),
               cert[:16], len(cert) // 2,
               ADJ_SIGNING_ID, HEADERS_ID,
               CLIENT_SDK, NATIVE_VERSION, ADJ_VERIFICATION,
               _cfg.get("head_phase", "(default 2b)"), api_host()))


# =======================================================================
# PART 9 — SELF-TEST: 9 genuine device captures frozen INSIDE this file
# (3 creditsea SDK-5.8.0 + 6 penti SDK-5.7.0): the claims law per capture
# plus the full 192-B mints, byte-exact.  No external resource is needed —
# the file is complete on its own.
# =======================================================================
GOLD_JSON = r"""@@GOLD@@"""
GOLD_VECTORS = json.loads(GOLD_JSON)


def self_test(verbose=True):
    """Claims-law check: build every capture's #10 string, compare sha256."""
    ok = True
    for g in GOLD_VECTORS:
        raw = build_claims(g["map"], g["kind"])
        sha = hashlib.sha256(raw).hexdigest()
        good = len(raw) == g["unpadded_len"] and sha == g["claims_sha256"]
        if verbose:
            print("[SIGNER] law  %-9s %-11s len=%3d (want %3d)  %s"
                  % (g["app"], g["kind"], len(raw), g["unpadded_len"],
                     "OK" if good else "FAIL"))
        ok &= good
    return ok


def self_test_blob(verbose=True):
    """Full-blob check: mint every genuine capture from (second, S, claims,
    d9, head) and require byte equality."""
    ok = True
    dt = 0.0
    for g in GOLD_VECTORS:
        t0 = time.perf_counter()
        blob = sign_pure(g["second"], g["S"], g["map"],
                         d9_hex=g["d9_hex"], kind=g["kind"],
                         head=tuple(g["head"]))
        dt = max(dt, time.perf_counter() - t0)
        good = blob.hex() == g["blob_hex"]
        if verbose:
            print("[SIGNER] blob %-9s %-11s second=%d  %s  (%.2f ms)"
                  % (g["app"], g["kind"], g["second"],
                     "BYTE-EXACT" if good else "FAIL", dt * 1000.0))
        ok &= good
    if verbose and GOLD_VECTORS:
        print("[SIGNER] worst signing: %.2f ms" % (dt * 1000.0))
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv or "--vm" in sys.argv:
        _t0 = time.perf_counter()
        _ok = self_test()
        _ok = self_test_blob() and _ok
        print("[SIGNER] self_test -> %s (%.2f s total)"
              % ("OK" if _ok else "FAIL", time.perf_counter() - _t0),
              flush=True)
        sys.exit(0 if _ok else 1)
    print("[SIGNER] adj9_signer — the adj9 signature algorithm in closed "
          "form (stdlib only).")
    print("[SIGNER] use: configure(campaign_data) -> sign(params, kind) "
          "-> auth_header(blob)")
    print("[SIGNER] test: python adj9_signer.py --selftest")
