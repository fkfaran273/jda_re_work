"""t7 -- raw adrp page histogram; per-func imports; region mnemonic profiles."""
import struct, json, bisect
from collections import defaultdict, Counter

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
TEXT_OFF, TEXT_SIZE = 0x8be0, 0x13fdd4
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fstarts = [f[0] for f in fdes]
fend = {f[0]: f[0]+f[1] for f in fdes}
fsize = {f[0]: f[1] for f in fdes}
gotplt = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/gotplt.json"))["gotplt"]
gotplt_by_addr = {int(k, 16): v for k, v in gotplt.items()}

def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'
def func_of(a):
    i = bisect.bisect_right(fstarts, a) - 1
    if i >= 0 and fstarts[i] <= a < fstarts[i] + fsize[fstarts[i]]:
        return fstarts[i]
    return None

# ---- raw decode: adrp pages, bl targets, blr, br --------------------------
page_hist = Counter()                  # page -> count
page_to_func = defaultdict(set)        # page -> funcs referencing
bl_edges = []                          # (site, target)
blr_sites = []
br_sites = []
adrp_sites = []
addr = TEXT_OFF; end = TEXT_OFF + TEXT_SIZE
while addr < end:
    w = struct.unpack_from('<I', d, addr)[0]
    op = w >> 24
    if (w & 0x9F000000) == 0x90000000:      # adrp
        rd = w & 31
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= 1 << 21
        page = ((addr + (imm << 12)) & ~0xFFF) & 0xFFFFFFFFFFFFFFFF
        page_hist[page] += 1
        f = func_of(addr)
        if f: page_to_func[page].add(f)
        adrp_sites.append((addr, rd, page))
    elif (w & 0xFC000000) == 0x94000000:    # bl
        imm = w & 0x3FFFFFF
        if imm & (1 << 25): imm -= 1 << 26
        bl_edges.append((addr, addr + imm * 4))
    elif (w & 0xFC000000) == 0xD6000000:
        if (w & 0xFFFFFC1F) == 0xD63F0000:  # blr xN
            blr_sites.append(addr)
        elif (w & 0xFFFFFC1F) == 0xD61F0000:  # br xN
            br_sites.append(addr)
    addr += 4

print("=== adrp page histogram (pages referenced >= 5 times) ===")
DRR_pages = {0x14c000, 0x14d000}
for pg, n in page_hist.most_common(40):
    if n >= 5:
        funcs = page_to_func[pg]
        print("  %s: %d refs in %d funcs  %s" % (hex(pg), n, len(funcs),
              ("*** DRR PAGE *** funcs: " + ",".join(hex(x) for x in sorted(funcs)[:12])) if pg in DRR_pages else ""))

print("\n=== DRR page (0x14c000/0x14d000) referencing functions, full ===")
drrf = set()
for pg in DRR_pages:
    drrf |= page_to_func.get(pg, set())
for f in sorted(drrf):
    print("  %s (%s) size=%d" % (hex(f), region(f), fsize[f]))
print("  total:", len(drrf))

# who bl's into the DRR-reading funcs? not needed yet.

# ---- per-function PLT imports ---------------------------------------------
plt_start, plt_end = 0x1489c0, 0x1489c0 + 0x4a0
bl_by_func = defaultdict(list)
for site, tgt in bl_edges:
    f = func_of(site)
    if f is not None:
        bl_by_func[f].append(tgt)

imports_by_func = {}
for f, ts in bl_by_func.items():
    imps = set()
    for t in ts:
        if plt_start <= t < plt_end:
            # plt stub: each 16B entry; adrp+ldr from got.plt; entry index = (t - plt_start)//16 - 1?
            # map: find got.plt addr used in stub -- simpler: gotplt sorted; plt entry i -> gotplt[i]
            idx = (t - plt_start) // 16
            imps.add(("PLT%d" % idx, t))
    imports_by_func[f] = imps

# plt entry -> got offset: disassemble first instrs of each plt stub quickly
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
plt_map = {}
ad = plt_start
adrpv = {}
while ad < plt_end:
    for ins in md.disasm(d[ad:ad+16], ad):
        if ins.mnemonic == 'adrp':
            r, pg = ins.op_str.split(', ')
            adrpv[r] = int(pg.lstrip('#'), 0)
        elif ins.mnemonic == 'ldr' and adrpv:
            ops = ins.op_str
            b = ops.find('[')
            if b != -1:
                inner = ops[b+1:ops.find(']')].split(',')
                base = inner[0].strip()
                off = int(inner[1].strip().lstrip('#'), 0) if len(inner) > 1 else 0
                if base in adrpv:
                    plt_map[ad] = adrpv[base] + off
        break_after = (ins.mnemonic == 'br')
    ad += 16
name_of_plt = {}
for stub, got in plt_map.items():
    nm = gotplt_by_addr.get(got)
    if nm: name_of_plt[stub] = nm

print("\n=== functions using imports (by category) ===")
cat = {
 'env_files': {'fopen','fgets','fclose','fread','fseek','ftell','opendir','readdir','closedir','readlink','stat','fstat','access','mmap','munmap','read','close','__system_property_get','getauxval'},
 'net': {'socket','sendto','setsockopt','connect','recvfrom','inet_aton'},
 'time': {'clock_gettime','gettimeofday','time','localtime','strftime','timer_create','timer_settime','fmod'},
 'rand': {'rand','srand'},
 'mem': {'malloc','calloc','realloc','free','memcpy','__memcpy_chk','memset','strlen','__strlen_chk','strdup','strcmp','strncmp','strchr','sscanf','strtol','vsnprintf'},
 'sync': {'pthread_mutex_lock','pthread_mutex_unlock','pthread_cond_wait','pthread_cond_timedwait','pthread_cond_signal','pthread_cond_broadcast','pthread_once','pthread_create','pthread_detach','pthread_condattr_init','pthread_condattr_setclock','pthread_cond_init','pthread_condattr_destroy'},
 'misc': {'syscall','getpid','__android_log_print','__cxa_finalize','__cxa_atexit','__stack_chk_fail'},
}
func_cats = defaultdict(set)
for f, imps in imports_by_func.items():
    names = set(name_of_plt.get(t, '?') for _, t in imps)
    for c, ns in cat.items():
        if names & ns:
            func_cats[c].add(f)
for c in ('env_files','net','time','rand','sync','mem','misc'):
    fs = sorted(func_cats[c])
    byreg = Counter(region(f) for f in fs)
    print("  %-10s %3d funcs  by region: %s" % (c, len(fs), dict(sorted(byreg.items()))))

print("\n=== functions with NO imports and NO calls (leaf compute) per region ===")
leafs = defaultdict(list)
for f, z in fsize.items():
    if f not in bl_by_func:
        leafs[region(f)].append(f)
for r in sorted(leafs):
    tot = sum(fsize[f] for f in leafs[r])
    print("  %s: %d leaf funcs, %d bytes" % (r, len(leafs[r]), tot))

# save bl edges for later
json.dump({"edges": [[a, b] for a, b in bl_edges]},
          open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/edges.json", "w"))

# ---- region mnemonic profiles via capstone --------------------------------
print("\n=== region mnemonic profiles ===")
prof = defaultdict(Counter)
for s, z in fdes:
    r = region(s)
    for ins in md.disasm(d[s:s+z], s):
        prof[r][ins.mnemonic] += 1
for r in sorted(prof):
    tot = sum(prof[r].values())
    top = ", ".join("%s=%d(%.1f%%)" % (m, n, 100.0*n/tot) for m, n in prof[r].most_common(12))
    print("  %s (n=%d): %s" % (r, tot, top))
print("\n  distinctive mnemonics: 'blr' per region:",
      {r: prof[r]['blr'] for r in prof},
      " 'br':", {r: prof[r]['br'] for r in prof},
      " SIMD(fp/vec):",
      {r: sum(n for m, n in prof[r].items() if m and (m.startswith('f') or m.startswith('ld1') or m.startswith('st1') or m.startswith('umull') or m.startswith('sq') or m.startswith('uq'))) for r in prof})
