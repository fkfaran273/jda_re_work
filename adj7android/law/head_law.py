# Fresh header-law probe: is blob[:16] minted by bionic random() (TYPE_3)
# seeded with the signing second?  draws: 310 warm-up discarded, then 8 values,
# pair-XORed, big-endian.
import json, re, sys, urllib.parse, struct, datetime

def glibc_random(seed):
    r = [0] * 344
    r[0] = seed & 0xFFFFFFFF
    for i in range(1, 31):
        # r[i] = (16807 * r[i-1]) % 2147483647  via signed trick
        hi, lo = divmod(r[i - 1], 127773)
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += 2147483647
        r[i] = word
    for i in range(31, 34):
        r[i] = r[i - 31]
    for i in range(34, 344):
        r[i] = (r[i - 31] + r[i - 3]) & 0xFFFFFFFF
    out = []
    for i in range(344, 344 + 320):
        r.append((r[i - 31] + r[i - 3]) & 0xFFFFFFFF)
        out.append(r[-1] >> 1)
    return out

def header_candidate(sec):
    vals = glibc_random(sec)
    drawn = vals[310:318]            # 310 discarded, take 8
    pairs = [drawn[0] ^ drawn[1], drawn[2] ^ drawn[3],
             drawn[4] ^ drawn[5], drawn[6] ^ drawn[7]]
    return b"".join(struct.pack(">I", p) for p in pairs)

def sent_sec(entry):
    q = entry["url"]
    if entry["method"] == "POST" and entry.get("body"):
        m = re.search(r"sent_at=([^&]+)", entry["body"])
    else:
        m = re.search(r"sent_at=([^&]+)", q)
    if not m:
        return None
    s = urllib.parse.unquote(m.group(1))
    s = s.replace("Z+0530", "").replace("+0530", "")
    dt = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f")
    return int(dt.replace(tzinfo=datetime.timezone(datetime.timedelta(hours=5, minutes=30))).timestamp())

for cap in ["payruki_signed.json", "hunch_signed.json"]:
    rows = json.load(open("../cap/" + cap))
    print("==", cap)
    for e in rows:
        if "blob" not in e:
            continue
        blob = bytes.fromhex(e["blob"])
        head = blob[:16]
        s0 = sent_sec(e)
        found = []
        for dsec in range(-4, 5):
            if header_candidate(s0 + dsec) == head:
                found.append(s0 + dsec)
        print("sid %3d head %s sent@%d match=%s" %
              (e["sid"], head.hex(), s0, found or "NONE"))
