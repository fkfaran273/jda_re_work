"""F_fit_candidate.py - DATA-DRIVEN result of the independent fit of the
adj9 fill transform F.

    region(V, pid, tid) -> (d0, d2, d4)   144 B, 4 B, 32 B (big-endian)

WHAT THIS IS
------------
The parametric transform F was NOT recovered.  An exhaustive fit over 21
distinct (V, pid, tid) labels and 205 candidate PRF/hash variants, plus a
377-function per-word elementary-law search and a 16-bit PRG positional sweep,
produced ZERO byte-exact reproductions (see F_FIT_FINDINGS.md).  The avalanche
core of the region (d0 = 144 B and d4 = 32 B) is a custom VM hash, not any
standard family.

Consequently `region()` below is a CAPTURED-TABLE ORACLE, not a derived
formula: it reproduces the region byte-exactly for every labelled pair and
raises UnknownRegion for any (V, pid, tid) that was not captured.  It does not
fabricate output for unseen inputs.

WHAT *WAS* SOLVED (exact, holds on 21/21 labels)
-------------------------------------------------
  The top half of descriptor #2 is a pure byte-swap of V's low half:
      d2 >> 16  ==  byteswap16(V & 0xFFFF)                (21/21 exact)
  Equivalently  d2 = byteswap32( g8(V,pid) | (V & 0xFFFF) ),  where the low
  16 bits of the pre-swap word come from V verbatim and g8 is an 8-bit value
  that depends on pid (and weakly on V) but NOT on tid.  Observed g8-derived
  low halves of d2:  pid 12345 -> 0x9B5A, pid 12346 -> 0x985A,
  pid 70000 -> 0xD27B; changing tid alone leaves d2 unchanged.  g8 itself is
  NOT modelled for unseen V, so #2 is fully reproduced only via the table
  (d2_from_V below gives the exact V-determined half).

STRUCTURAL LAWS (verified on the table, see check_laws())
----------------------------------------------------------
  L1: tile[0] ^ tile[2] == R||R  (both 16-bit halves equal), R = low half
  L2: d4[6] >> 16 == R
  L3: d0[1] == tile's word at d0[1]'s phase  --  HOLDS ON DEVICE CORPUS (12/13),
      FAILS IN THE EMULATOR (0/21), matching fill_model.md section 4.
"""
import struct

__all__ = ["region", "region_words", "d2_from_V", "check_laws", "tile_R",
           "UnknownRegion", "TABLE_SIZE", "DISTINCT_V"]

M32 = 0xFFFFFFFF


class UnknownRegion(LookupError):
    """Raised for a (V, pid, tid) that is not in the captured table.

    F is unsolved for unseen inputs; this module refuses to invent bytes."""


# (V, pid, tid, d0_hex, d2_hex, d4_hex)
_TABLE = (
    (1789005928, 12345, 12346, "15fd7b7781ef6fb58dadfba719bfca0d2815d28dfd2b0bdbf169ba8b58931f33657b2e99cc811371f169ba8b58931f33657b2e99cc811371f169ba8b58931f33657b2e99cc811371f169ba8b58931f33657b2e99cc811371f169ba8b58931f33657b2e99cc811371f169ba8b58931f33657b2e99cc811371f169ba8b58931f33657b2e99cc811371f169ba8b58931f33", "68109b5a", "10005000010061009000200291421048b150410680d098509412a9fae2183633"),  # era2 T+1000
    (1789006848, 12345, 12346, "3a6ffb91879d6e77dd0fb1ff8917e5e78fbde34d76ab8b6f0655d52fd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f", "00149b5a", "010001800300410042900a00601002186002281472868b9054188d3a6cf00c0d"),  # era1 androidid
    (1789006848, 12345, 12347, "3a6ffb916e77dd0fb1ff8917e5e78fbde34d76ab8b6fd52f54e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f00ffe1358dc5381754e7b52dd9dde79f", "00149b5a", "010001800300410042900a00601002186002281472868b9054188d3a6cf00c0d"),  # era2 fit_tidonly
    (1789006848, 12346, 12346, "912bce9ff28c99be831afa19e0bdda51c0f5fce6c398ae7eb20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93c", "0014985a", "0001000500200224028006851400342134ad40a93486123163a732791aa4ffa0"),  # era2 fit_pidonly
    (1789006848, 12346, 12347, "912bce9ff28c99be831afa19e0bdda51c0f5fce6c398ae7eb20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93cd1a9f974e3d0a8aab20e9ad38077d93c", "0014985a", "0001000500200224028006851400342134ad40a93486123163a732791aa4ffa0"),  # era2 pidtid
    (1789006848, 70000, 80000, "3eaefdff181cd8e71386fe55353402bdc9dc2c3f59e460dd527e48df83be928574cc6e6da50c991f527e48df83be928574cc6e6da50c991f527e48df83be928574cc6e6da50c991f527e48df83be928574cc6e6da50c991f527e48df83be928574cc6e6da50c991f527e48df83be928574cc6e6da50c991f527e48df83be928574cc6e6da50c991f527e48df83be9285", "0014d27b", "00020800080a004802020288030012c8280261ca03aa2d2826b2d1c0cb6197af"),  # era2 fit_pidtid2
    (1789006849, 12345, 12346, "0b984e85726c2f6d52de56992b2a8faef21dcef442cff7f3627d9fbfe20c3f7c1b89e64b9bf81fce627d9fbfe20c3f7c1b89e64b9bf81fce627d9fbfe20c3f7c1b89e64b9bf81fce627d9fbfe20c3f7c1b89e64b9bf81fce627d9fbfe20c3f7c1b89e64b9bf81fce627d9fbfe20c3f7c1b89e64b9bf81fce627d9fbfe20c3f7c1b89e64b9bf81fce627d9fbfe20c3f7c", "01149b5a", "00200004080401241104582419642940684c6041181c594679f480717db30e76"),  # era2 e2_sec1
    (1789006850, 12345, 12346, "a3ca4a0ffbab9166bfc7c907e7a64dc26363d2c77afb88cf3e9788fea65f545a66f6d09ffe3e10363e9788fea65f545a66f6d09ffe3e10363e9788fea65f545a66f6d09ffe3e10363e9788fea65f545a66f6d09ffe3e10363e9788fea65f545a66f6d09ffe3e10363e9788fea65f545a66f6d09ffe3e10363e9788fea65f545a66f6d09ffe3e10363e9788fea65f545a", "02149b5a", "00010400000801000c09050c09150a190031460583081c0d586198c82ea14866"),  # era2 T+2
    (1789006851, 12345, 12346, "ee8dc6429c61373a1c9d45d66e7126a40d035720b541b7fc35bd8f78a4df9ee64751fd94d6331e1a35bd8f78a4df9ee64751fd94d6331e1a35bd8f78a4df9ee64751fd94d6331e1a35bd8f78a4df9ee64751fd94d6331e1a35bd8f78a4df9ee64751fd94d6331e1a35bd8f78a4df9ee64751fd94d6331e1a35bd8f78a4df9ee64751fd94d6331e1a35bd8f78a4df9ee6", "03149b5a", "0200010020002b000808a808aa0c0184388412cc8394f21072ec91622ba75472"),  # era2 T+3
    (1789006852, 12345, 12346, "6dddd59638cf55c46f7f00d63a6d9f36a58d48d40c3e5ef45b8efc77c6cc36850e9ca96593de61355b8efc77c6cc36850e9ca96593de61355b8efc77c6cc36850e9ca96593de61355b8efc77c6cc36850e9ca96593de61355b8efc77c6cc36850e9ca96593de61355b8efc77c6cc36850e9ca96593de61355b8efc77c6cc36850e9ca96593de61355b8efc77c6cc3685", "04149b5a", "004010001100110213403140308212c3a2831482d54002a255129d423abb96a4"),  # era2 T+4
    (1789006853, 12345, 12346, "ba5419809cd21c147bc13a925d473b0c5cd9d98b2ad73819cdc46a1a0dcf4d02eb424c9c2b49aa11cdc46a1a0dcf4d02eb424c9c2b49aa11cdc46a1a0dcf4d02eb424c9c2b49aa11cdc46a1a0dcf4d02eb424c9c2b49aa11cdc46a1a0dcf4d02eb424c9c2b49aa11cdc46a1a0dcf4d02eb424c9c2b49aa11cdc46a1a0dcf4d02eb424c9c2b49aa11cdc46a1a0dcf4d02", "05149b5a", "0200100011002000100161013121c101520320072312c1952686c00b67d5de94"),  # era2 T+5
    (1789006854, 12345, 12346, "dbdbfebad3fcb73ec2b9bf19ca9e4d0b388c15ca13db0edb029e9c69e9ee665c0ab9944ee1c97719029e9c69e9ee665c0ab9944ee1c97719029e9c69e9ee665c0ab9944ee1c97719029e9c69e9ee665c0ab9944ee1c97719029e9c69e9ee665c0ab9944ee1c97719029e9c69e9ee665c0ab9944ee1c97719029e9c69e9ee665c0ab9944ee1c97719029e9c69e9ee665c", "06149b5a", "0100000203000340006002c203f082d092b2027341a319620827eb707587ed8c"),  # era2 fit_u500006
    (1789006855, 12345, 12346, "db15af47d8c278d11c1c7b061fcb6b360ffb787e88927d324c4cffb89b75ec5f4f9bfc6f98a228814c4cffb89b75ec5f4f9bfc6f98a228814c4cffb89b75ec5f4f9bfc6f98a228814c4cffb89b75ec5f4f9bfc6f98a228814c4cffb89b75ec5f4f9bfc6f98a228814c4cffb89b75ec5f4f9bfc6f98a228814c4cffb89b75ec5f4f9bfc6f98a228814c4cffb89b75ec5f", "07149b5a", "000200030041004900c30402040d8482828ac245d441c70903d7d73964cda9dc"),  # era2 fit_u500007
    (1789006856, 12345, 12346, "a351b694a359cc38bdf3cc30bdfb0cb47d7f68b2fe977df4e03d4fd03e1b8f5ce0354fd83e1391f6e03d4fd03e1b8f5ce0354fd83e1391f6e03d4fd03e1b8f5ce0354fd83e1391f6e03d4fd03e1b8f5ce0354fd83e1391f6e03d4fd03e1b8f5ce0354fd83e1391f6e03d4fd03e1b8f5ce0354fd83e1391f6e03d4fd03e1b8f5ce0354fd83e1391f6e03d4fd03e1b8f5c", "08149b5a", "000210021004020611000a0618861aa432240be47aa41ea20008de2671cba3da"),  # era2 fit_u500008
    (1789006858, 12345, 12346, "59e1b9b744f0cea761ecd3b67cfd2c3d83767e318a6de7b5af71c7bc68f72526b260daad75e6003aaf71c7bc68f72526b260daad75e6003aaf71c7bc68f72526b260daad75e6003aaf71c7bc68f72526b260daad75e6003aaf71c7bc68f72526b260daad75e6003aaf71c7bc68f72526b260daad75e6003aaf71c7bc68f72526b260daad75e6003aaf71c7bc68f72526", "0a149b5a", "00800880088400140a142a14089ca08c2009a1896a01380d1d11c786af4b3d22"),  # era2 T+10
    (1789006864, 12345, 12346, "7dd403cf3fcc63c2f3f521dab1ed0f4f9f78a37bcbbd392307843707a7305b8a459c751fe52897b307843707a7305b8a459c751fe52897b307843707a7305b8a459c751fe52897b307843707a7305b8a459c751fe52897b307843707a7305b8a459c751fe52897b307843707a7305b8a459c751fe52897b307843707a7305b8a459c751fe52897b307843707a7305b8a", "10149b5a", "0040001008501850004414140c6000010e24147922158e214218a0b49037db8f"),  # era2 fit_u500016
    (1789006974, 12345, 12346, "48d9cb85f86b7d81d868cd3368da6a18cff1fc1fde4d7836fe4e6c3dc9d47ba44efcdc8f79665ba7fe4e6c3dc9d47ba44efcdc8f79665ba7fe4e6c3dc9d47ba44efcdc8f79665ba7fe4e6c3dc9d47ba44efcdc8f79665ba7fe4e6c3dc9d47ba44efcdc8f79665ba7fe4e6c3dc9d47ba44efcdc8f79665ba7fe4e6c3dc9d47ba44efcdc8f79665ba7fe4e6c3dc9d47ba4", "7e149b5a", "10005000002000210004500840881022140b149806b690b1b0b2379aa5e9ff1e"),  # era2 Tsame
    (1789006975, 12345, 12346, "49b74ddbf3b1bf7a03d1057cb9d774f3c8587632c1f23ed13192b6d00a7b7d598b940cd6b07d8d393192b6d00a7b7d598b940cd6b07d8d393192b6d00a7b7d598b940cd6b07d8d393192b6d00a7b7d598b940cd6b07d8d393192b6d00a7b7d598b940cd6b07d8d393192b6d00a7b7d598b940cd6b07d8d393192b6d00a7b7d598b940cd6b07d8d393192b6d00a7b7d59", "7f149b5a", "0800020008010101210100802aa060018801028548a74a66ba063be9bcabbf3e"),  # era2 T-1sec
    (1789007332, 12345, 12346, "70d07cbaed5c21b38a5cbc3f17d04c71e79e767850192d74371996343ddbfbf6aa950bb8a0579cf6371996343ddbfbf6aa950bb8a0579cf6371996343ddbfbf6aa950bb8a0579cf6371996343ddbfbf6aa950bb8a0579cf6371996343ddbfbf6aa950bb8a0579cf6371996343ddbfbf6aa950bb8a0579cf6371996343ddbfbf6aa950bb8a0579cf6371996343ddbfbf6", "e4159b5a", "10008000804000418241a2010a00a244bb40a180c085fa8c9d8c0ac2abefba3a"),  # era2 T+100
    (1789031184, 12345, 12346, "ddafa56235b44def9ca1a5f474baeb713a3faae994b5e66e3da0e365322b45fbd5bb0b7eda30ecee3da0e365322b45fbd5bb0b7eda30ecee3da0e365322b45fbd5bb0b7eda30ecee3da0e365322b45fbd5bb0b7eda30ecee3da0e365322b45fbd5bb0b7eda30ecee3da0e365322b45fbd5bb0b7eda30ecee3da0e365322b45fbd5bb0b7eda30ecee3da0e365322b45fb", "10739b5a", "01000108000a05088400844281520d4a050b0d890096410ee81b0f8bd14e01fe"),  # era2 T+10000
    (1789694880, 12345, 12346, "12950ad1817eb8783cbf2b93af54da905e57d5f80bdc5998b61dedf369348f1b25f67e18fadf32dab61dedf369348f1b25f67e18fadf32dab61dedf369348f1b25f67e18fadf32dab61dedf369348f1b25f67e18fadf32dab61dedf369348f1b25f67e18fadf32dab61dedf369348f1b25f67e18fadf32dab61dedf369348f1b25f67e18fadf32dab61dedf369348f1b", "a093955a", "0001040000402401a041804220618409b46ba24a21422e2a93ebdf2984c7155a"),  # era2 fit_u600000
)

TABLE_SIZE = len(_TABLE)
DISTINCT_V = len(set(t[0] for t in _TABLE))

_INDEX = {(t[0], t[1], t[2]): t for t in _TABLE}


def region(V, pid, tid):
    """V = tv_sec ^ tv_usec at the fill instant (int < 2**32); pid/tid ints.

    Returns (d0, d2, d4) as raw bytes: 144 / 4 / 32, big-endian packed.
    Byte-exact for every labelled pair; raises UnknownRegion otherwise.
    """
    t = _INDEX.get((V, pid, tid))
    if t is None:
        raise UnknownRegion(
            "no captured region for V=0x%08x pid=%d tid=%d (F unsolved for "
            "unseen inputs)" % (V, pid, tid))
    return (bytes.fromhex(t[3]), bytes.fromhex(t[4]), bytes.fromhex(t[5]))


def region_words(V, pid, tid):
    """Same as region() but unpacked: d0 = 36 ints, d2 = 1 int, d4 = 8 ints."""
    d0, d2, d4 = region(V, pid, tid)
    return (struct.unpack(">36I", d0), struct.unpack(">I", d2)[0],
            struct.unpack(">8I", d4))


def _bswap16(x):
    return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)


def _bswap32(x):
    return struct.unpack(">I", struct.pack("<I", x & M32))[0]


def d2_from_V(V):
    """The 16 bits of descriptor #2 that are determined by V alone.

    Returns d2_high16 = byteswap16(V & 0xFFFF)  (exact, 21/21 labels).
    The low half of #2 is a per-pid constant; get the exact word from
    region() for a captured (V, pid, tid).
    """
    return _bswap16(V & 0xFFFF)


def d2_reconstruct(V, low16):
    """Full #2 word once the per-pid low half is supplied."""
    return ((_bswap16(V & 0xFFFF) << 16) | (low16 & 0xFFFF)) & M32


def tile_R(d0):
    """Locate the 4-word repeating tile in d0 and return (phase, C, R).

    d0 = [W0, X, 4 head words, tile * 7.25].  R is the replicated 16-bit value
    of L1; returns (None, None, None) when no clean cycle is found.
    """
    w = struct.unpack(">36I", d0)
    for s in range(0, 13):
        C = w[s:s + 4]
        if len(C) < 4:
            break
        if all(w[i] == C[(i - s) % 4] for i in range(s, 36)):
            x = C[0] ^ C[2]
            if (x >> 16) == (x & 0xFFFF):
                return s, C, x & 0xFFFF
    return None, None, None


def check_laws(d0, d2, d4):
    """Evaluate L1/L2/L3 on a region.  Returns a dict of booleans + R."""
    s, C, R = tile_R(d0)
    w = struct.unpack(">36I", d0)
    d2w = struct.unpack(">I", d2)[0]
    d4w = struct.unpack(">8I", d4)
    L1 = s is not None
    L2 = s is not None and (d4w[6] >> 16) == R
    L3 = s is not None and w[1] == C[(1 - s) % 4]
    return {"L1": L1, "L2": L2, "L3": L3, "R": R, "phase": s}


def check_laws_V(V, d0, d2, d4):
    """L1/L2/L3 plus the solved #2 relations (V supplied explicitly)."""
    r = check_laws(d0, d2, d4)
    d2w = struct.unpack(">I", d2)[0]
    r["d2_high16_is_bswap16V"] = (d2w >> 16) == _bswap16(V & 0xFFFF)
    r["d2_low_byte_is_5A"] = (d2w & 0xFF) == 0x5A
    return r


if __name__ == "__main__":
    ok = {"L1": 0, "L2": 0, "L3": 0, "d2hi==bswap16(V)": 0}
    for (V, pid, tid, h0, h2, h4) in _TABLE:
        d0, d2, d4 = bytes.fromhex(h0), bytes.fromhex(h2), bytes.fromhex(h4)
        r = check_laws_V(V, d0, d2, d4)
        ok["L1"] += r["L1"]; ok["L2"] += r["L2"]; ok["L3"] += r["L3"]
        ok["d2hi==bswap16(V)"] += r["d2_high16_is_bswap16V"]
    n = TABLE_SIZE
    print("table: %d labels, %d distinct V" % (n, DISTINCT_V))
    for k, v in ok.items():
        print("  %s: %d/%d" % (k, v, n))
