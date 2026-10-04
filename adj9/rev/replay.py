"""replay.py — symbolic byte-level replay of the FinEx wire log.  v3

Tracks a GF(2) byte-vector per (stream, absolute position).  Reads (LENQ on
ANY stream) between two EMITs form the read-group of the next write.  A write
is modeled, by value matching, as one of:
  xor of the read-group            (mask == XOR of read masks)
  xor of the read-group + constant (interned const row, e.g. the 0x55 sweep)
  copy of a single read
Word-size writes (the 4-byte word assembly) decompose into 4 byte lanes, each
matched against the read-group in order.

Sources: the first write to a position.  Record positions (MAIN 1134..1278)
are marked UNKNOWN (the decoder's unknowns); everything else keeps its value
from the log and must reproduce identically between runs that share
claims+second (validated by the caller).
"""
from collections import defaultdict

MAIN = 0x5450001000
REC0, REC1 = 1134, 1278          # record byte area (absolute)


class Replay:
    def __init__(self, unknown_range=(REC0, REC1)):
        self.vec = {}                 # (sva, pos) -> int mask
        self.val = {}                 # (sva, pos) -> last concrete value
        self.rows = []                # row -> ("src", key, val|None) | ("const", val)
        self.row_val = []
        self.const_rows = {}
        self.reads = []               # (poskey, mask, val) since last E
        self.stats = defaultdict(int)
        self.flags = defaultdict(int)
        self.ur = unknown_range

    def new_source(self, key, val):
        r = len(self.rows)
        unknown = (key[0] == MAIN and self.ur[0] <= key[1] < self.ur[1])
        self.rows.append(("src", key))
        self.row_val.append(None if unknown else val)
        return r

    def new_const(self, val):
        r = self.const_rows.get(val)
        if r is None:
            r = len(self.rows)
            self.const_rows[val] = r
            self.rows.append(("const", val))
            self.row_val.append(val)
        return r

    def feed(self, ev):
        kind = ev[0]
        if kind == "Q":
            _, pc, sva, top, n, v = ev
            key = (sva, top + n)
            self.reads.append((key, self.vec.get(key), v))
        elif kind == "E":
            _, pc, sva, top, n, v = ev
            key = (sva, top + n)
            R = self.reads
            self.reads = []
            if key not in self.vec:
                # first write -> source row
                r = self.new_source(key, v)
                self.vec[key] = 1 << r
                self.val[key] = v
                self.stats["src"] += 1
                return
            if v <= 0xFF:
                self._byte_write(key, v, R)
            else:
                self._word_write(key, v, R)

    # ---- models ---------------------------------------------------------
    def _match_xor(self, R, v):
        mask = 0
        xv = 0
        for (k, m, val) in R:
            if m is None:
                return None
            mask ^= m
            xv ^= val
        c = xv ^ (v & 0xFF if v <= 0xFF else None or v)
        return mask, xv

    def _byte_write(self, key, v, R):
        # try xor-of-group
        mask = 0
        xv = 0
        ok = all(m is not None for (_, m, _) in R)
        if ok and R:
            for (_, m, val) in R:
                mask ^= m
                xv ^= val
            c = xv ^ v
            if c == 0:
                self.vec[key] = mask
                self.val[key] = v
                self.stats["xor"] += 1
                return
            if c in self.const_rows or len(self.const_rows) < 48:
                self.vec[key] = mask | (1 << self.new_const(c))
                self.val[key] = v
                self.stats["xor+c"] += 1
                if c not in self.const_rows or True:
                    return
                return
        # single-read copy
        for (k, m, val) in R:
            if m is not None and val == v:
                self.vec[key] = m
                self.val[key] = v
                self.stats["copy"] += 1
                return
        # xor + new const (flag: may be model breakdown)
        mask = 0
        xv = 0
        for (_, m, val) in R:
            if m is not None:
                mask ^= m
                xv ^= val
        cr = self.new_const(xv ^ v)
        self.vec[key] = mask | (1 << cr)
        self.val[key] = v
        self.stats["xor+newconst"] += 1
        self.flags["nc"] += 1

    def _word_write(self, key, v, R):
        """4-lane word write: each output byte is a copy of one read byte."""
        bs = [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]
        used = [False] * len(R)
        lanes = []
        for b in bs:
            hit = None
            for i, (k, m, val) in enumerate(R):
                if not used[i] and m is not None and val == b:
                    hit = i
                    break
            if hit is None:
                lanes.append(None)
                self.flags["wordlane-miss"] += 1
            else:
                used[hit] = True
                lanes.append(R[hit][1])
        # store per-lane masks in val-keyed side table
        self.word_lanes = getattr(self, "word_lanes", {})
        self.word_lanes[key] = lanes
        self.val[key] = v
        self.stats["word"] += 1

    def finish(self):
        """Body equations: 36 words at MAIN [620..656) -> 144 byte masks."""
        out = []
        wl = getattr(self, "word_lanes", {})
        for k in range(36):
            key = (MAIN, 620 + k)
            lanes = wl.get(key)
            if lanes is None:
                out.extend([None] * 4)
                continue
            # blob word bytes are big-endian: byte0 = lanes[0] (v>>24)
            out.extend(lanes)
        return out


def build(wirelog, unknown_range=(REC0, REC1)):
    rp = Replay(unknown_range)
    for ev in wirelog:
        rp.feed(ev)
    return rp, rp.finish()


def solve(eq, rp, body):
    """Solve the unknown record sources from a target body (144 bytes).

    Returns (record{pos:val}, rank, free, status).
    """
    rec_rows = [(r, key[1]) for r, (k, key) in enumerate(rp.rows)
                if k == "src" and key[0] == MAIN and rp.row_val[r] is None
                and REC0 <= key[1] < REC1]
    rec_rows.sort(key=lambda t: t[1])
    j_of_row = {r: j for j, (r, p) in enumerate(rec_rows)}
    n = len(rec_rows)
    if n != REC1 - REC0:
        return None, "record source rows = %d (expected 144)" % n
    known_vals = {r: v for r, v in enumerate(rp.row_val) if v is not None}

    A = [0] * 144
    rhs = [0] * 144
    for m in range(144):
        mask = eq[m]
        if mask is None:
            return None, "no equation for body byte %d" % m
        coef = 0
        acc = 0
        mm = mask
        while mm:
            b = mm & -mm
            r = b.bit_length() - 1
            mm ^= b
            j = j_of_row.get(r)
            if j is not None:
                coef |= 1 << j
            else:
                v = known_vals.get(r)
                if v is None:
                    return None, "row %d neither known nor record" % r
                acc ^= v
        A[m] = coef
        rhs[m] = body[m] ^ acc

    rowlist = [(A[m], rhs[m]) for m in range(144)]
    where = [-1] * 144
    r = 0
    for c in range(144):
        bit = 1 << c
        pivr = None
        for i in range(r, len(rowlist)):
            if rowlist[i][0] & bit:
                pivr = i
                break
        if pivr is None:
            continue
        rowlist[r], rowlist[pivr] = rowlist[pivr], rowlist[r]
        for i in range(len(rowlist)):
            if i != r and (rowlist[i][0] & bit):
                rowlist[i] = (rowlist[i][0] ^ rowlist[r][0],
                              rowlist[i][1] ^ rowlist[r][1])
        where[c] = r
        r += 1
    rank = r
    for i in range(rank, len(rowlist)):
        if rowlist[i][0] == 0 and rowlist[i][1] != 0:
            return None, "inconsistent (rank %d)" % rank
    x = [0] * 144
    for c in range(144):
        if where[c] >= 0:
            x[c] = rowlist[where[c]][1]
    rec = {rec_rows[j][1]: x[j] for j in range(144)}
    return (rec, rank, 144 - rank), "rank=%d free=%d" % (rank, 144 - rank)
