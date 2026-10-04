"""Minimal TLS 1.2/1.3 ClientHello / ServerHello parser for pcap-free
fingerprint extraction from passthrough-proxy byte logs.  Pure stdlib.

parse_client_hello(data) -> dict or None   (data = raw c2s stream start)
parse_server_hello(data) -> dict or None   (data = raw s2c stream start)
"""
import struct

EXT_NAMES = {
    0: "server_name", 1: "max_fragment_length", 5: "status_request",
    10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms",
    14: "use_srtp", 15: "heartbeat", 16: "alpn", 17: "status_request_v2",
    18: "signed_certificate_timestamp", 19: "client_certificate_type",
    20: "server_certificate_type", 21: "padding", 22: "encrypt_then_mac",
    23: "extended_master_secret", 24: "token_binding", 26: "compress_certificate",
    27: "session_ticket", 28: "record_size_limit", 29: "pwd_protect",
    30: "pwd_clear", 31: "password_salt", 32: "ticket_pinning",
    33: "tls_cert_with_extern_psk", 34: "delegated_credentials",
    35: "session_ticket_v2", 41: "pre_shared_key", 42: "early_data",
    43: "supported_versions", 44: "cookie", 45: "psk_key_exchange_modes",
    47: "certificate_authorities", 48: "oid_filters", 49: "post_handshake_auth",
    50: "signature_algorithms_cert", 51: "key_share", 52: "transparency_info",
    53: "connection_id", 55: "external_id_hash", 56: "external_session_id",
    57: "quic_transport_parameters", 58: "ticket_request",
    13172: "next_protocol_negotiation",
    17513: "application_settings", 30032: "channel_id",
    65281: "renegotiation_info", 65486: "alps",
}

GROUP_NAMES = {
    0x001d: "x25519", 0x001e: "x448", 0x0017: "secp256r1", 0x0018: "secp384r1",
    0x0019: "secp521r1", 0x001a: "x25519_kyber768", 0x6399: "x25519_kyber768_draft00",
    0x11ec: "x25519_ml_kem768", 0x4588: "x25519_kyber768_draft00_alias",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x001c: "brainpoolP256r1",
    0x001b: "brainpoolP384r1", 0x001a + 0x100: "secp256r1_custom",
}

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xc02f: "ECDHE-RSA-AES128-GCM-SHA256", 0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xc013: "ECDHE-RSA-AES128-SHA", 0xc014: "ECDHE-RSA-AES256-SHA",
    0xc009: "ECDHE-ECDSA-AES128-SHA", 0xc00a: "ECDHE-ECDSA-AES256-SHA",
    0x009c: "RSA-PSK-AES128-GCM-SHA256", 0x009e: "DHE-RSA-AES128-GCM-SHA256",
    0x00aa: "DHE-PSK-AES128-GCM-SHA256", 0x00a2: "DHE-PSK-AES256-GCM-SHA384",
    0x006b: "DHE-RSA-AES256-SHA256", 0x0067: "DHE-RSA-AES128-SHA256",
    0x003c: "DH-RSA-AES128-SHA256", 0x003d: "DH-RSA-AES256-SHA256",
    0x002f: "AES128-SHA", 0x0035: "AES256-SHA", 0x00ff: "EMPTY_RENEGOTIATION_INFO_SCSV",
    0xcca8: "ECDHE-RSA-CHACHA20-POLY1305", 0xcca9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xccab: "DHE-RSA-CHACHA20-POLY1305", 0xcc13: "ECDHE-RSA-CHACHA20-POLY1305_OLD",
    0xcc14: "ECDHE-ECDSA-CHACHA20-POLY1305_OLD", 0xcc15: "DHE-RSA-CHACHA20-POLY1305_OLD",
    0xc007: "ECDHE-ECDSA-CAMELLIA128-SHA256", 0x0041: "CAMELLIA128-SHA",
    0x0084: "CAMELLIA256-SHA", 0x00ba: "CAMELLIA128-SHA256", 0x00c0: "CAMELLIA256-SHA384",
}


def _rec(data, off=0):
    """TLS record -> (type, version, payload, next_off) or None."""
    if len(data) < off + 5:
        return None
    t = data[off]
    ver = struct.unpack(">H", data[off + 1:off + 3])[0]
    ln = struct.unpack(">H", data[off + 3:off + 5])[0]
    if off + 5 + ln > len(data):
        return None
    return t, ver, data[off + 5:off + 5 + ln], off + 5 + ln


def _hs(payload):
    """Handshake payload -> (type, body)."""
    if len(payload) < 4:
        return None, None
    t = payload[0]
    ln = int.from_bytes(payload[1:4], "big")
    if len(payload) < 4 + ln:
        return None, None
    return t, payload[4:4 + ln]


def parse_client_hello(data):
    r = _rec(data)
    if not r or r[0] != 0x16:
        return None
    _, recver, payload, _ = r
    t, body = _hs(payload)
    if t != 0x01 or body is None:
        return None
    ver = struct.unpack(">H", body[0:2])[0]
    o = 2 + 32
    sidlen = body[o]; o += 1
    sid = body[o:o + sidlen]; o += sidlen
    cslen = struct.unpack(">H", body[o:o + 2])[0]; o += 2
    ciphers = [struct.unpack(">H", body[o + i:o + i + 2])[0]
               for i in range(0, cslen, 2)]
    o += cslen
    complen = body[o]; o += 1
    comp = list(body[o:o + complen]); o += complen
    exts = []
    if o + 2 <= len(body):
        extlen = struct.unpack(">H", body[o:o + 2])[0]
        o += 2
        end = o + extlen
        while o + 4 <= end and o + 4 <= len(body):
            et, el = struct.unpack(">HH", body[o:o + 4])
            exts.append((et, body[o + 4:o + 4 + el]))
            o += 4 + el
    out = {
        "record_version": "0x%04x" % recver,
        "legacy_version": "0x%04x" % ver,
        "session_id_len": sidlen,
        "cipher_suites": ["0x%04x%s" % (c, " " + CIPHER_NAMES[c] if c in CIPHER_NAMES else "")
                          for c in ciphers],
        "compression": comp,
        "extensions_order": [EXT_NAMES.get(e, "unknown(%d)" % e) for e, _ in exts],
        "extensions_raw": [{"type": EXT_NAMES.get(e, "unknown(%d)" % e), "code": e,
                            "len": len(d)} for e, d in exts],
    }
    for e, d in exts:
        if e == 0:  # server_name
            try:
                ln = struct.unpack(">H", d[1:3])[0]
                out["sni"] = d[5:5 + ln].decode("latin1")
            except Exception:
                pass
        elif e == 10:  # supported_groups
            n = struct.unpack(">H", d[0:2])[0]
            out["supported_groups"] = ["0x%04x %s" % (
                struct.unpack(">H", d[2 + i:4 + i])[0],
                GROUP_NAMES.get(struct.unpack(">H", d[2 + i:4 + i])[0], ""))
                for i in range(0, n, 2)]
        elif e == 11:  # ec_point_formats
            out["ec_point_formats"] = ["%d" % b for b in d[1:]]
        elif e == 13:  # signature_algorithms
            n = struct.unpack(">H", d[0:2])[0]
            out["signature_algorithms"] = ["0x%04x" % struct.unpack(
                ">H", d[2 + i:4 + i])[0] for i in range(0, n, 2)]
        elif e == 16:  # alpn
            out["alpn_offer"] = []
            i = 2
            while i < 2 + struct.unpack(">H", d[0:2])[0] and i + 1 <= len(d):
                l = d[i]; i += 1
                out["alpn_offer"].append(d[i:i + l].decode("latin1"))
                i += l
        elif e == 43:  # supported_versions
            if d and d[0] == len(d) - 1:
                out["supported_versions"] = ["0x%04x" % struct.unpack(
                    ">H", d[1 + i:3 + i])[0] for i in range(0, len(d) - 1, 2)]
        elif e == 45:  # psk_key_exchange_modes
            out["psk_modes"] = ["%d" % b for b in d[1:]]
        elif e == 51:  # key_share
            n = struct.unpack(">H", d[0:2])[0]
            ks = []
            i = 2
            while i + 4 <= 2 + n:
                g, klen = struct.unpack(">HH", d[i:i + 4])
                ks.append("0x%04x %s (len=%d)" % (g, GROUP_NAMES.get(g, ""), klen))
                i += 4 + klen
            out["key_share"] = ks
        elif e == 26:  # compress_certificate
            n = d[0]
            out["certificate_compression"] = ["%d" % struct.unpack(
                ">H", d[1 + i:3 + i])[0] for i in range(0, n, 2)]
        elif e == 17513:  # application settings
            out["alps"] = True
    return out


def parse_server_hello(data):
    r = _rec(data)
    if not r or r[0] != 0x16:
        return None
    _, recver, payload, _ = r
    t, body = _hs(payload)
    if t != 0x02 or body is None:
        return None
    ver = struct.unpack(">H", body[0:2])[0]
    o = 2 + 32
    sidlen = body[o]; o += 1 + sidlen
    cipher = struct.unpack(">H", body[o:o + 2])[0]; o += 2
    comp = body[o]; o += 1
    exts = []
    if o + 2 <= len(body):
        extlen = struct.unpack(">H", body[o:o + 2])[0]
        o += 2
        end = o + extlen
        while o + 4 <= end and o + 4 <= len(body):
            et, el = struct.unpack(">HH", body[o:o + 4])
            exts.append((et, body[o + 4:o + 4 + el]))
            o += 4 + el
    out = {
        "record_version": "0x%04x" % recver,
        "server_version": "0x%04x" % ver,
        "cipher": "0x%04x %s" % (cipher, CIPHER_NAMES.get(cipher, "")),
        "extensions_order": [EXT_NAMES.get(e, "unknown(%d)" % e) for e, _ in exts],
    }
    for e, d in exts:
        if e == 43 and len(d) == 2:
            out["tls_version_negotiated"] = "0x%04x" % struct.unpack(">H", d)[0]
        elif e == 16:  # ALPN chosen (plaintext only in TLS<=1.2)
            l = d[2] if len(d) > 2 else 0
            out["alpn_negotiated"] = d[3:3 + l].decode("latin1")
        elif e == 0:
            try:
                ln = struct.unpack(">H", d[1:3])[0]
                out["sni_ack"] = d[5:5 + ln].decode("latin1")
            except Exception:
                pass
    return out


def ja3_alike(ch):
    """Deterministic fingerprint string from the parsed ClientHello."""
    if not ch:
        return None
    parts = [
        ch.get("legacy_version", ""),
        ",".join(c.split()[0] for c in ch["cipher_suites"]),
        ",".join(str(x) for x in ch["compression"]),
        ",".join(ch["extensions_order"]),
    ]
    g = ch.get("supported_groups")
    parts.append(",".join(x.split()[0] for x in g) if g else "")
    parts.append(",".join(ch.get("signature_algorithms", [])))
    al = ch.get("alpn_offer")
    parts.append(",".join(al) if al else "")
    sv = ch.get("supported_versions")
    parts.append(",".join(sv) if sv else "")
    ks = ch.get("key_share")
    parts.append(",".join(x.split()[0] for x in ks) if ks else "")
    return "|".join(parts)


if __name__ == "__main__":
    import sys
    d = open(sys.argv[1], "rb").read()
    which = sys.argv[2] if len(sys.argv) > 2 else "c"
    if which == "c":
        ch = parse_client_hello(d)
        print(ja3_alike(ch))
        for k, v in (ch or {}).items():
            print("%-24s %s" % (k, v))
    else:
        sh = parse_server_hello(d)
        for k, v in (sh or {}).items():
            print("%-24s %s" % (k, v))
