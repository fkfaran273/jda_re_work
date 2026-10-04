"""Map TLS record boundaries in a proxy tunnel to wire timestamps from the
device tcpdump pcap (LINKTYPE_LINUX_SLL).  Reconstructs one TCP direction's
byte stream from TCP seq numbers, then assigns each TLS record the timestamp
of the first packet covering it."""
import struct
import sys

PCAP = "cap_fp.pcap"
SPORT, DPORT = 37782, 8889  # device tunnel: device:37782 <-> PC:8889


def parse_pcap(path):
    d = open(path, "rb").read()
    pkts = []
    off = 24
    while off + 16 <= len(d):
        ts, tus, caplen, origlen = struct.unpack("<IIII", d[off:off + 16])
        pkt = d[off + 16:off + 16 + caplen]
        pkts.append((ts + tus / 1e6, pkt))
        off += 16 + caplen
    return pkts


def sll_ip(pkt):
    if len(pkt) < 16:
        return None
    et = struct.unpack(">H", pkt[14:16])[0]
    if et != 0x0800:
        return None
    return pkt[16:]


def parse_tcp(ip):
    ihl = (ip[0] & 0xF) * 4
    proto = ip[9]
    if proto != 6:
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    t = ip[ihl:]
    sport, dport = struct.unpack(">HH", t[0:4])
    seq, ack = struct.unpack(">II", t[4:12])
    doff = (t[12] >> 4) * 4
    flags = t[13]
    payload = t[doff:]
    return src, sport, dst, dport, seq, flags, payload


def main():
    pkts = parse_pcap(PCAP)
    t0 = pkts[0][0]
    segs = []  # (time, dir, seq, payload)
    for tt, pkt in pkts:
        ip = sll_ip(pkt)
        if not ip:
            continue
        p = parse_tcp(ip)
        if not p:
            continue
        src, sport, dst, dport, seq, flags, payload = p
        if not payload and not (flags & 0x02 or flags & 0x01):
            continue
        if dport == DPORT and sport == SPORT:
            segs.append((tt - t0, "c2s", seq, payload, flags))
        elif sport == DPORT and dport == SPORT:
            segs.append((tt - t0, "s2c", seq, payload, flags))
    # rebuild streams per direction
    for direction in ("c2s", "s2c"):
        ds = [s for s in segs if s[1] == direction]
        base = min(s[2] for s in ds)
        stream = bytearray()
        covers = []  # (start, end, time) in stream coords
        for _, d2, seq, payload, flags in sorted(ds, key=lambda s: s[2]):
            rel = seq - base - 1  # SYN consumed one seq byte
            if rel < 0 or flags & 0x02:
                continue
            end = rel + len(payload)
            if end <= len(stream):
                continue  # retransmission/dup
            if rel > len(stream):
                covers.append((len(stream), rel, None))  # gap
            stream.extend(payload[len(stream) - rel:] if rel < len(stream) else payload)
            covers.append((rel, end, _))
        # map TLS records (skip CONNECT exchange: 175B c2s request + 39B s2c 200)
        skip = {"c2s": 175, "s2c": 39}[direction]
        print("=== %s stream (%d bytes; TLS records from offset %d) ==="
              % (direction, len(stream), skip))
        off = skip
        while off + 5 <= len(stream):
            t = stream[off]
            ln = struct.unpack(">H", stream[off + 3:off + 5])[0]
            tend = None
            for a, b, tt in covers:
                if a <= off < b:
                    tend = tt
                    break
            desc = {0x16: "Handshake", 0x14: "CCS", 0x17: "AppData",
                    0x15: "Alert"}.get(t, "?")
            if t == 0x16 and off + 5 < len(stream) and stream[off + 5] == 1:
                desc = "ClientHello"
            elif t == 0x16 and off + 5 < len(stream) and stream[off + 5] == 2:
                desc = "ServerHello"
            print("  off=%5d type=0x%02x %-11s len=%5d  first_on_wire_at=%.3fs"
                  % (off, t, desc, ln, tend if tend is not None else -1))
            off += 5 + ln
    # packet timeline (size+flags) for connection-level view
    print("=== packet timeline (tunnel) ===")
    for tt, direction, seq, payload, flags in segs:
        fl = ("S" if flags & 0x02 else "") + ("F" if flags & 0x01 else "") \
             + ("R" if flags & 0x04 else "")
        print("  %.3f %s seq=%u len=%d %s" % (tt, direction, seq, len(payload), fl))


if __name__ == "__main__":
    main()
