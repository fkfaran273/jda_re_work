"""t1_elfmap.py -- parse eh_frame FDEs, relocations, dynsym, .data dumps."""
import struct, json, sys

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()

eh_frame_off, eh_frame_size = 0x43a8, 0x482c
eh = d[eh_frame_off:eh_frame_off + eh_frame_size]

# ---- parse CIE/FDE chain -------------------------------------------------
pos = 0
cies = {}
fdes = []
while pos < len(eh):
    start = pos
    length = struct.unpack_from('<I', eh, pos)[0]
    if length == 0:
        break
    if length == 0xFFFFFFFF:
        length = struct.unpack_from('<Q', eh, pos + 4)[0]
        hdr = 12
    else:
        hdr = 4
    end = pos + hdr + length
    cid = struct.unpack_from('<I', eh, pos + hdr)[0]
    if cid == 0:  # CIE
        # version at pos+hdr+4
        p = pos + hdr + 4
        v = eh[p]; p += 1
        z = eh.index(b'\0', p)
        aug = eh[p:z].decode(); p = z + 1
        fde_enc = None
        if 'z' in aug:
            # parse augmentation data: (LH, FDE enc, ...) for 'zR'
            # read uleb128 augdatalen
            alen = 0; shift = 0
            while True:
                b = eh[p]; p += 1
                alen |= (b & 0x7f) << shift; shift += 7
                if not (b & 0x80): break
            aend = p + alen
            # code align (uleb), data align (sleb), ret reg (uleb)
            while True:
                b = eh[p]; p += 1
                if not (b & 0x80): break
            while True:
                b = eh[p]; p += 1
                if not (b & 0x80): break
            while True:
                b = eh[p]; p += 1
                if not (b & 0x80): break
            if 'R' in aug:
                fde_enc = eh[p]; p += 1
        cies[start] = fde_enc if fde_enc is not None else 0x1b
    else:
        # FDE: cie pointer is (pos+hdr) + cid
        cie_addr = (pos + hdr) + cid
        enc = cies.get(cie_addr, 0x1b)
        p = pos + hdr + 4
        # pc_begin encoded at p; assume pcrel sdata4 (enc 0x1b) or 0x10/0x11
        fmt = enc & 0x0f
        appl = enc & 0x70
        if fmt in (0x0b, 0x0c, 0x0a, 0x09):  # sdata4/udata4
            val = struct.unpack_from('<i' if fmt == 0x0b else '<I', eh, p)[0]
            if appl & 0x10:  # pcrel
                pcbegin = (eh_frame_off + p) + val
            else:
                pcbegin = val
            p += 4
        elif fmt in (0x01, 0x02):  # data2/4 abs
            pcbegin = struct.unpack_from('<H', eh, p)[0] if fmt == 1 else struct.unpack_from('<I', eh, p)[0]
            p += 2 if fmt == 1 else 4
        else:
            raise ValueError("enc %#x at %#x" % (enc, eh_frame_off + p))
        if fmt in (0x0b, 0x0c, 0x0a, 0x09):
            val = struct.unpack_from('<I', eh, p)[0]
            pcrange = val
            p += 4
        elif fmt == 0x01:
            pcrange = struct.unpack_from('<H', eh, p)[0]; p += 2
        else:
            pcrange = struct.unpack_from('<I', eh, p)[0]; p += 4
        fdes.append((pcbegin, pcrange))
    pos = end

fdes.sort()
print("FDE count:", len(fdes))
overlaps = 0
for i in range(1, len(fdes)):
    if fdes[i][0] < fdes[i-1][0] + fdes[i-1][1]:
        overlaps += 1
        if overlaps < 10:
            print("  overlap:", hex(fdes[i-1][0]), hex(fdes[i-1][1]), "->", hex(fdes[i][0]))
print("overlapping FDEs:", overlaps)
total_cov = sum(f[1] for f in fdes)
print("total covered bytes:", total_cov, "of .text 0x13fdd4 =", 0x13fdd4)
print("text span:", hex(0x8be0), "-", hex(0x8be0 + 0x13fdd4))
print("first fde:", hex(fdes[0][0]), fdes[0][1], " last fde end:", hex(fdes[-1][0] + fdes[-1][1]))

# gaps between consecutive FDEs
gaps = []
for i in range(1, len(fdes)):
    g = fdes[i][0] - (fdes[i-1][0] + fdes[i-1][1])
    if g > 0:
        gaps.append((fdes[i-1][0] + fdes[i-1][1], g))
print("num gaps:", len(gaps), "gap bytes total:", sum(g[1] for g in gaps))
for g in sorted(gaps, key=lambda x: -x[1])[:15]:
    print("  big gap: start", hex(g[0]), "len", g[1], hex(g[1]))

json.dump({"fdes": fdes}, open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json", "w"))

# ---- relocations ---------------------------------------------------------
rela_off, rela_size = 0x10f8, 0x1da0
print("\n--- RELA.DYN (%d entries) ---" % (rela_size // 24))
relats = {0x403: 'JUMP_SLOT', 0x401: 'GLOB_DAT', 0x101: 'ABS64', 0x403 & 0xffffffff: 'JUMP_SLOT'}
init_arr = {}
drr = {}   # data.rel.ro values
got = {}
counts = {}
for i in range(rela_size // 24):
    off = rela_off + i * 24
    r_off, r_info, r_add = struct.unpack_from('<QQq', d, off)
    t = r_info & 0xffffffff
    sym = r_info >> 32
    counts[t] = counts.get(t, 0) + 1
    if 0x14d7d0 <= r_off < 0x14d7e0:
        init_arr[r_off] = r_add
print("rela type counts:", {hex(k): v for k, v in counts.items()})
print("init_array relocs:", {hex(k): hex(v) for k, v in sorted(init_arr.items())})

# raw init_array bytes
print("init_array raw:", d[0x1497d0:0x1497e0].hex())
print("fini_array raw:", d[0x1497c0:0x1497d0].hex())

# ---- dynsym imports ------------------------------------------------------
print("\n--- DYNSYM (75 entries) ---")
dynsym_off, dynsym_size = 0x2f8, 0x708
dynstr_off = 0xd5c
syms = []
for i in range(dynsym_size // 24):
    o = dynsym_off + i * 24
    name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', d, o)
    end = d.index(b'\0', dynstr_off + name)
    nm = d[dynstr_off + name:end].decode()
    bind = info >> 4
    typ = info & 0xf
    syms.append((nm, bind, typ, value, shndx))
for nm, bind, typ, value, shndx in syms:
    if nm:
        print("  bind=%d type=%d val=%s shndx=%d %s" % (bind, typ, hex(value), shndx, nm))

# ---- rela.plt -> PLT mapping --------------------------------------------
print("\n--- RELA.PLT ---")
rp_off, rp_size = 0x2e98, 0x6c0
gotplt = {}
for i in range(rp_size // 24):
    o = rp_off + i * 24
    r_off, r_info, r_add = struct.unpack_from('<QQq', d, o)
    sym = r_info >> 32
    gotplt[r_off] = syms[sym][0] if sym < len(syms) else '?'
for k in sorted(gotplt):
    print("  GOT.PLT %s -> %s" % (hex(k), gotplt[k]))
json.dump({"gotplt": {hex(k): v for k, v in gotplt.items()}},
          open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/gotplt.json", "w"))

# ---- .data / .data.rel.ro / .bss dump ------------------------------------
print("\n--- .data.rel.ro (0x960 bytes @0x14ce60, file 0x148e60) ---")
drr_data = d[0x148e60:0x148e60 + 0x960]
# print nonzero qwords
nz = 0
for i in range(0, len(drr_data), 8):
    v = struct.unpack_from('<Q', drr_data, i)[0]
    if v:
        nz += 1
        if nz <= 60:
            print("  %s: %016x" % (hex(0x14ce60 + i), v))
print("  ... total nonzero qwords:", nz)

print("\n--- .data (0x360a bytes @0x151c20, file 0x149c20) ---")
data = d[0x149c20:0x149c20 + 0x360a]
nz = 0
for i in range(0, len(data), 8):
    v = struct.unpack_from('<Q', data, i)[0]
    if v:
        nz += 1
        if nz <= 80:
            print("  %s: %016x" % (hex(0x151c20 + i), v))
print("  ... total nonzero qwords:", nz, "of", len(data)//8)
