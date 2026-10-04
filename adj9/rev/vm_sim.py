"""vm_sim.py - flat symbolic executor for the wire-builder VM (fn 0x100094..0x12aa44).

The whole function is one instruction stream:
  0x100228      LENQ tail (start of the VM program; head preload already modeled)
  0x10034c/354  glue: mem[0] += stack-top residue; mem[mem[0]-1] = 0; stack-top := old mem[0]
  0x100554      dispatch head: if queue empty -> exit; w0 = POP queue; tree follows inline
  0x12a8c0      trampoline: PUSH next-opcode into queue; goto glue 0x100354
Objects: arg1[0] data stack, arg1[1] mem, arg1[2] loop list, arg1[3] opcode queue,
arg1[4+k] descriptor #k (preloaded with its captured word count).

Run: python vm_sim.py
"""
import sys, re
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev')
import scan_rand as S
from collections import deque


def pt(o):
    try: return int(o.replace('#', ''), 16)
    except: return None


INS = [x for x in S.INSNS if 0x100094 <= x[0] < 0x12aa48]
BY = {a: i for i, (a, m, o) in enumerate(INS)}
FN_LO, FN_HI = 0x100094, 0x12aa48
CONDS = {'b.lo': lambda a, c: a < c, 'b.lt': lambda a, c: a < c,
         'b.le': lambda a, c: a <= c, 'b.ls': lambda a, c: a <= c,
         'b.hs': lambda a, c: a >= c, 'b.ge': lambda a, c: a >= c,
         'b.gt': lambda a, c: a > c, 'b.eq': lambda a, c: a == c,
         'b.ne': lambda a, c: a != c}

# descriptor word counts known from captures: #0=36, #2=1, #4=8, #8=4, #9=5; #7=claims
DESC_LEN = {4: 36, 6: 1, 8: 8, 12: 4, 13: 5}
DESC_NAME = {4: '#0', 5: '#1', 6: '#2', 7: '#3', 8: '#4', 9: '#5', 10: '#6',
             11: '#7', 12: '#8', 13: '#9', 14: '#10'}


class Sym:
    __slots__ = ('kind', 'val', 'a', 'b', 'op')

    def __init__(self, kind, val=None, a=None, b=None, op=None):
        self.kind = kind; self.val = val; self.a = a; self.b = b; self.op = op

    def __repr__(self):
        if self.kind == 'const': return '0x%x' % self.val
        if self.kind == 'rand': return 'R%d' % self.val
        if self.kind == 'desc': return 'D%d[%d]' % (self.val, self.b)
        if self.kind == 'op': return '(%s %s %s @0x%x)' % (self.op, self.a, self.b, self.val)
        if self.kind == 'load': return 'M?%r' % (self.a,)
        if self.kind == 'len': return 'LEN%d' % self.val
        return '%s%r' % (self.kind, self.val)


def sim(maxsteps=300000, trace=True, start=0x100228):
    stack = []
    queue = deque()
    mem = {1: {}}
    base = {1: [0]}; topn = {1: 1}; cursor = {1: 0}
    for k in range(4, 15):
        mem[k] = {}
        n = DESC_LEN.get(k)
        if n is not None:
            for i2 in range(n): mem[k][i2] = Sym('desc', k, b=i2)
        base[k] = [0]; topn[k] = 1; cursor[k] = n if n is not None else 0
    loops = []
    rand_n = 0
    draws = []
    stores = []
    opcodes_run = []
    REGS = {}
    CMP = (None, None)
    X28_OBJ = None
    XREG = {}  # x-register -> object id (for x24-style indirect object refs)
    pc = start
    steps = 0

    def konst(x):
        return x if isinstance(x, int) else (x.val if isinstance(x, Sym) and x.kind == 'const' else None)

    def back_set(i, pat, span=12):
        # stop at 'bl' or unconditional 'b': a jump-in means the operand was set by the jumper
        for j in range(i - 1, max(0, i - span), -1):
            a2, m2, o2 = INS[j]
            mm = re.match(pat, o2)
            if mm: return mm
            if m2 == 'bl' or m2 == 'b': return None
        return None

    def eff_addr(objid, off):
        return base[objid][topn[objid] - 1] + off

    def rnd():
        nonlocal rand_n
        r = Sym('rand', rand_n); rand_n += 1
        draws.append(r)
        return r

    while True:
        steps += 1
        if steps > maxsteps:
            print('STEP LIMIT at 0x%x' % pc); break
        if pc not in BY:
            import traceback; traceback.print_stack()
            print('PC off instructions %r' % pc); break
        if pc == 0x100318:
            print('=== NORMAL EXIT (queue drained) after %d steps' % steps); break
        a, m, o = INS[BY[pc]]
        if trace and m in ('bl', 'b',) or (trace and (m.startswith('b.') or m in ('cbz', 'cbnz'))):
            pass
        # ---- control / special ----
        if m == 'b':
            t = pt(o)
            if t == 0x12a8c0:
                nx = None
                mm = back_set(BY[pc], r'^w2, (.+)$')
                if mm:
                    s = mm.group(1)
                    if s.startswith('#'): nx = int(s[1:], 16) if s[1:].startswith('0x') else int(s[1:])
                    elif re.match(r'^w\d+$', s):
                        print('DYNAMIC NEXT at 0x%x (%s)' % (a, s)); break
                if nx is None:
                    print('tramp w/o imm at 0x%x' % a); break
                opcodes_run.append(nx)
                queue.append(nx)
                if trace: print('0x%x NEXT=0x%x (q=%s)' % (a, nx, [hex(x) for x in queue]))
                pc = 0x100354; continue
            if t in (0x100318, 0x12aa44, 0x100088):
                print('=== EXIT 0x%x at 0x%x (err flag path)' % (t, a)); break
            if trace and t not in (0x100354,): print('0x%x b -> 0x%x' % (a, t))
            pc = t; continue
        if m in ('cbz', 'cbnz') and o.startswith('w8,'):
            t8 = pt(o.split(',')[1])
            if m == 'cbz': pc = t8
            else: pc = pc + 4
            continue
        if m == 'tbnz':
            parts = o.split(',')
            r, bit, tgt = parts[0], parts[1], pt(parts[2])
            v = konst(REGS.get(r))
            if v is None:
                print('tbnz unknown at 0x%x' % a); break
            if (v >> int(bit.strip()[1:])) & 1:
                if trace: print('0x%x tbnz taken -> 0x%x (queue empty exit)' % (a, tgt))
                pc = tgt
            else:
                pc = pc + 4
            continue
        if m in ('tbz',):
            parts = o.split(',')
            r, bit, tgt = parts[0], parts[1], pt(parts[2])
            v = konst(REGS.get(r))
            if v is None:
                print('tbz unknown at 0x%x' % a); break
            pc = tgt if not ((v >> int(bit.strip()[1:])) & 1) else pc + 4
            continue
        if m in CONDS:
            t = pt(o)
            if t is None:
                print('BAD TARGET %s %s at 0x%x' % (m, o, a)); break
            v1, v2 = CMP
            k1, k2 = konst(v1), konst(v2)
            if k1 is None or k2 is None:
                print('DATA-UNKNOWN BRANCH %s at 0x%x cmp(%r,%r)' % (m, a, v1, v2)); break
            if CONDS[m](k1, k2):
                if trace: print('0x%x %s taken -> 0x%x' % (a, m, t))
                pc = t
            else:
                pc = pc + 4
            continue
        if m in ('cbz', 'cbnz'):
            r = o.split(',')[0]
            t = pt(o.split(',')[1])
            v = konst(REGS.get(r))
            if v is None:
                print('DATA-UNKNOWN %s at 0x%x (%s)' % (m, a, r)); break
            taken = (v == 0) if m == 'cbz' else (v != 0)
            if taken:
                if trace: print('0x%x %s taken -> 0x%x' % (a, m, t))
                pc = t
            else: pc = pc + 4
            continue
        if m == 'ret':
            print('=== RET at 0x%x' % a); break
        # ---- queue fetch ----
        if m == 'bl' and o == '#0x146474':
            REGS['w0'] = Sym('const', 1 if not queue else 0)
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x146478':
            if not queue:
                print('queue underflow at 0x%x' % a); break
            REGS['w0'] = Sym('const', queue.popleft())
            if trace: print('0x%x FETCH op=0x%x  [stack depth %d: %s]' % (a, REGS['w0'].val, len(stack), [str(x)[:18] for x in stack[-4:]]))
            pc = pc + 4; continue
        # ---- stack ops ----
        if m == 'bl' and o == '#0x147630':
            v = Sym('unk')
            mm = back_set(BY[pc], r'^w2, (.+)$')
            if mm:
                s = mm.group(1)
                if s.startswith('#'): v = Sym('const', int(s[1:], 16) if s[1:].startswith('0x') else int(s[1:]))
                elif s == 'wzr': v = Sym('const', 0)
                elif re.match(r'^w\d+$', s): v = REGS.get(s) or Sym('unk')
                else: v = REGS.get('w2') or Sym('unk')
            else:
                v = REGS.get('w2') or Sym('unk')
            stack.append(v)
            if trace: print('0x%x PUSH %s' % (a, v))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x146470':
            v = REGS.get('w2') or Sym('unk')
            kv = konst(v)
            if kv is None:
                print('DYNAMIC queue push at 0x%x' % a); break
            queue.append(kv)
            if trace: print('0x%x QUEPUSH 0x%x (q=%s)' % (a, kv, [hex(x) for x in queue]))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x147734':
            if not stack:
                print('POP EMPTY at 0x%x' % a); break
            v = stack.pop(); REGS['w0'] = v
            if trace: print('0x%x POP -> %s' % (a, v))
            pc = pc + 4; continue
        if m == 'bl' and o in ('#0x147a18', '#0x14784c', '#0x147a20'):
            n = None
            mm = back_set(BY[pc], r'^w2, (.+)$')
            if mm:
                s = mm.group(1)
                if s.startswith('#'): n = int(s[1:], 16) if s[1:].startswith('0x') else int(s[1:])
                elif re.match(r'^w\d+$', s): n = konst(REGS.get(s))
            if o == '#0x147a18': n = 0
            if n is None or len(stack) < n + 1:
                print('SWAP/DUP underflow at 0x%x n=%r depth=%d' % (a, n, len(stack))); break
            idx = -1 - n
            if o == '#0x147a20':
                stack[-1], stack[idx] = stack[idx], stack[-1]
                if trace: print('0x%x SWAP(%d)' % (a, n))
            else:
                stack.append(stack[idx])
                if trace: print('0x%x DUPOVER(%d) copy %s' % (a, n, stack[-1]))
            pc = pc + 4; continue
        # ---- mem ops ----
        if m == 'bl' and o == '#0x147304':
            w1 = None
            mm = back_set(BY[pc], r'^w1, (.+)$')
            if mm:
                s = mm.group(1)
                if s.startswith('#'): w1 = int(s[1:], 16) if s[1:].startswith('0x') else int(s[1:])
                elif re.match(r'^w\d+$', s): w1 = konst(REGS.get(s))
            x0obj = None
            for j in range(BY[pc] - 1, max(0, BY[pc] - 24), -1):
                a2, m2, o2 = INS[j]
                if m2 == 'ldr' and (o2.startswith('x0, [x28') or o2.startswith('x0, [x8')): x0obj = X28_OBJ; break
                if m2 == 'ldp' and o2.startswith('x21, x0, [x20]'): x0obj = 1; break
                if m2 == 'ldr' and re.match(r'^x0, \[x26[^\]]*\]!?$', o2): x0obj = 1; break
                if m2 == 'mov' and re.match(r'^x0, x(1[89]|2[0-8])$', o2):
                    x0obj = XREG.get(o2.split(', ')[1]); break
                if m2 == 'ldr' and re.match(r'^x(1[89]|2[0-8]), \[x2[0-9][^\]]*\]!?$', o2):
                    x0obj = X28_OBJ; break
                if m2 == 'ldr' and re.match(r'^x(1[89]|2[0-8]), \[x26[^\]]*\]!?$', o2):
                    x0obj = 1; break
            if x0obj is None or w1 is None:
                print('LOAD unknown at 0x%x obj=%r off=%r' % (a, x0obj, w1)); break
            addr = eff_addr(x0obj, w1)
            v = mem[x0obj].get(addr, Sym('const', 0))  # calloc-zeroed
            REGS['w0'] = v
            if trace: print('0x%x LOAD obj%d[off %s -> abs %d] -> %s' % (a, x0obj, w1, addr, v))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x146ed8':
            off = None
            mm = back_set(BY[pc], r'^w2, (.+)$')
            if mm:
                s = mm.group(1)
                if s.startswith('#'): off = int(s[1:], 16) if s[1:].startswith('0x') else int(s[1:])
                elif s == 'wzr': off = 0
                elif re.match(r'^w\d+$', s): off = konst(REGS.get(s))
                else: off = konst(REGS.get('w2'))
            v = REGS.get('w3')
            x1obj = None
            for j in range(BY[pc] - 1, max(0, BY[pc] - 24), -1):
                a2, m2, o2 = INS[j]
                if m2 == 'ldr' and re.match(r'^x1, \[x26[^\]]*\]!?$', o2): x1obj = 1; break
                if m2 == 'ldr' and re.match(r'^x1, \[x2[0-9][^\]]*\]!?$', o2): x1obj = X28_OBJ; break
                if m2 == 'ldr' and o2.startswith('x1, [x20]'): x1obj = 0; break
                if m2 == 'mov' and re.match(r'^x1, x(1[89]|2[0-8])$', o2):
                    x1obj = XREG.get(o2.split(', ')[1]); break
                if m2 == 'ldr' and re.match(r'^x(1[89]|2[0-8]), \[x26[^\]]*\]!?$', o2): x1obj = 1; break
                if m2 == 'ldr' and re.match(r'^x(1[89]|2[0-8]), \[x2[0-9][^\]]*\]!?$', o2): x1obj = X28_OBJ; break
            if x1obj in (None, 0) or off is None:
                print('STORE unknown at 0x%x obj=%r off=%r XREG=%r' % (a, x1obj, off, XREG)); break
            addr = eff_addr(x1obj, off)
            mem[x1obj][addr] = v
            if addr + 1 > cursor[x1obj]: cursor[x1obj] = addr + 1
            stores.append((x1obj, addr, v, a))
            if trace: print('0x%x STORE obj%d[off %s -> abs %d] = %s' % (a, x1obj, off, addr, v))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x1472e8':
            x0obj = None
            for j in range(BY[pc] - 1, max(0, BY[pc] - 24), -1):
                a2, m2, o2 = INS[j]
                if m2 == 'ldr' and (o2.startswith('x0, [x28') or o2.startswith('x0, [x8')): x0obj = X28_OBJ; break
                if m2 == 'mov' and re.match(r'^x0, x(1[89]|2[0-8])$', o2):
                    x0obj = XREG.get(o2.split(', ')[1]); break
                if m2 == 'ldr' and re.match(r'^x(1[89]|2[0-8]), \[x2[0-9][^\]]*\]!?$', o2):
                    x0obj = X28_OBJ; break
                if m2 == 'ldr' and re.match(r'^x(1[89]|2[0-8]), \[x26[^\]]*\]!?$', o2):
                    x0obj = 1; break
            L = cursor[x0obj] - base[x0obj][topn[x0obj] - 1]
            REGS['w0'] = Sym('const', L) if isinstance(L, int) else Sym('unk')
            if trace: print('0x%x OBJLEN obj%d = %d' % (a, x0obj, L))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x147120':
            x1obj = None
            for j in range(BY[pc] - 1, max(0, BY[pc] - 14), -1):
                a2, m2, o2 = INS[j]
                if m2 == 'ldr' and o2.startswith('x1, [x28]'): x1obj = X28_OBJ; break
                if m2 == 'ldr' and re.match(r'^x1, \[x26[^\]]*\]!?$', o2): x1obj = 1; break
                if m2 == 'bl': break
            base[x1obj].append(cursor[x1obj]); topn[x1obj] += 1
            if trace: print('0x%x FRAMEPUSH obj%d base=%d' % (a, x1obj, base[x1obj][-1]))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x147220':
            x1obj = None
            for j in range(BY[pc] - 1, max(0, BY[pc] - 14), -1):
                a2, m2, o2 = INS[j]
                if m2 == 'ldr' and o2.startswith('x1, [x28]'): x1obj = X28_OBJ; break
                if m2 == 'ldr' and re.match(r'^x1, \[x26[^\]]*\]!?$', o2): x1obj = 1; break
                if m2 == 'bl': break
            topn[x1obj] -= 1
            cursor[x1obj] = base[x1obj][topn[x1obj] - 1]
            if trace: print('0x%x FRAMEPOP obj%d back to %d' % (a, x1obj, cursor[x1obj]))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x146558':
            cnt = konst(REGS.get('w2'))
            loops.append(cnt)
            if trace: print('0x%x LOOPNEW cnt=%s' % (a, cnt))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x146650':
            c = loops[-1]
            if isinstance(c, int):
                loops[-1] = c - 1
                REGS['w0'] = Sym('const', c - 1)
            else:
                REGS['w0'] = Sym('unk')
            if trace: print('0x%x LOOPDEC cnt=%s' % (a, c))
            pc = pc + 4; continue
        if m == 'bl' and o == '#0x148d10':
            REGS['w0'] = rnd()
            if trace: print('0x%x RAND -> %s' % (a, REGS['w0']))
            pc = pc + 4; continue
        if m == 'bl':
            t = pt(o)
            if trace: print('0x%x bl 0x%x %s' % (a, t, S.PLT.get(t, '')))
            for r in ('w1', 'w2', 'w3'): REGS.pop(r, None)
            pc = pc + 4; continue
        # ---- ALU / mov / cmp ----
        mm = re.match(r'^(w\d+), (w\d+), (.+)$', o) if m in ('add', 'sub', 'mul', 'eor', 'and', 'orr', 'lsl', 'lsr') else None
        if mm:
            d, s1, s2 = mm.group(1), mm.group(2), mm.group(3)
            v1 = REGS.get(s1)
            if s2.startswith('w'): v2 = REGS.get(s2)
            elif s2.startswith('#'): v2 = int(s2[1:], 16) if s2[1:].startswith('0x') else int(s2[1:])
            else: v2 = int(s2)
            if isinstance(v1, Sym) and v1.kind == 'const': v1 = v1.val
            if isinstance(v2, Sym) and v2.kind == 'const': v2 = v2.val
            if isinstance(v1, int) and isinstance(v2, int):
                if m == 'add': r = (v1 + v2) & 0xffffffff
                elif m == 'sub': r = (v1 - v2) & 0xffffffff
                elif m == 'mul': r = (v1 * v2) & 0xffffffff
                elif m == 'eor': r = (v1 ^ v2) & 0xffffffff
                elif m == 'and': r = (v1 & v2) & 0xffffffff
                elif m == 'orr': r = (v1 | v2) & 0xffffffff
                elif m == 'lsl': r = (v1 << (v2 & 31)) & 0xffffffff
                else: r = (v1 >> (v2 & 31)) & 0xffffffff
                REGS[d] = Sym('const', r)
            else:
                REGS[d] = Sym('op', val=a, a=v1, b=v2, op=m)
            pc = pc + 4; continue
        if m == 'mov' and re.match(r'^w\d+, w\d+$', o):
            d, s = o.split(', '); REGS[d] = REGS.get(s); pc = pc + 4; continue
        if m == 'mov' and re.match(r'^w\d+, (wzr|#0x[0-9a-f]+|#\d+)$', o):
            d, s = o.split(', ')
            REGS[d] = Sym('const', 0) if s == 'wzr' else Sym('const', int(s[1:], 16) if s[1:].startswith('0x') else int(s[1:]))
            pc = pc + 4; continue
        if m == 'cmp' and re.match(r'^w\d+, (.+)$', o):
            s1, s2 = o.split(', ')
            v1 = REGS.get(s1)
            if s2.startswith('w'): v2 = REGS.get(s2)
            elif s2.startswith('#'): v2 = int(s2[1:], 16) if s2[1:].startswith('0x') else int(s2[1:])
            else: v2 = int(s2)
            CMP = (v1, v2); pc = pc + 4; continue
        if m == 'add' and re.match(r'^x8, x20, #0x10$', o):
            pc = pc + 4; continue  # x8 = &arg1[2] (loop-list ptr) bookkeeping
        if m == 'add' and re.match(r'^x(8|28), x20, w0, uxtw #3$', o):
            w0v = konst(REGS.get('w0'))
            if w0v is None:
                print('X28 obj unknown at 0x%x' % a); break
            X28_OBJ = 4 + w0v
            if trace: print('0x%x X28 -> obj%d (%s)' % (a, X28_OBJ, DESC_NAME.get(X28_OBJ, '?')))
            pc = pc + 4; continue
        if m == 'ldr' and re.match(r'^x0, \[x28(, #0x20)?\]!?$', o):
            if trace: print('0x%x x0 = obj%d (%s)' % (a, X28_OBJ, DESC_NAME.get(X28_OBJ, '?')))
            pc = pc + 4; continue
        if m == 'ldr' and re.match(r'^x\d+, \[x26[^\]]*\]!?$', o):
            XREG[o.split(',')[0]] = 1; pc = pc + 4; continue
        if m == 'ldr' and re.match(r'^x\d+, \[x2[0-9][^\]]*\]!?$', o):
            XREG[o.split(',')[0]] = X28_OBJ; pc = pc + 4; continue
        if m == 'mov' and re.match(r'^x\d+, x\d+$', o):
            d, s = o.split(', '); XREG[d] = XREG.get(s); pc = pc + 4; continue
        if m in ('ldr', 'str', 'stur', 'ldur', 'ldp', 'stp', 'nop', 'sxtw', 'ubfx',
                 'bfi', 'bfxil', 'rev', 'neg', 'mvn', 'tst'):
            pc = pc + 4; continue
        if m == 'mov' and re.match(r'^w\d+, #\d+$', o):
            pc = pc + 4; continue
        print('UNHANDLED %s %s at 0x%x' % (m, o, a)); break

    print()
    print('=== opcodes executed (%d): %s' % (len(opcodes_run), ' '.join('%x' % x for x in opcodes_run)))
    print('=== TOTAL RAND DRAWS = %d' % rand_n)
    print('=== stores into obj1 (scratch mem):')
    for ob, ad, v, sa in stores:
        if ob == 1: print('  M[%d] = %s   @0x%x' % (ad, v, sa))
    print('=== obj1 cursor=%d' % cursor[1])
    for k in range(4, 15):
        print('=== obj%d (%s): cursor=%d frame-len=%d words:' % (k, DESC_NAME[k], cursor[k], cursor[k] - base[k][topn[k] - 1]))
        for kk in sorted(mem[k]):
            print('    [%d] = %s' % (kk, mem[k][kk]))
    return draws, stores, mem, cursor


# ---------------------------------------------------------------------------
# FULL-PROGRAM driver (2026-09-23, vm_activation.md).
#
# The symbolic walker above cannot finish the program (halts at the 0x1bf9
# handler: its dataflow is pointer-derived).  The byte-exact full-program
# executor is fin_vm2.FinEx (verified: signing A reproduced 48/48 + 22,272
# native events 1:1, see fin_result.md).  These drivers run the REAL program
# end-to-end and measure the rand-stream consumption:
#
#   python vm_sim.py full     # all 10 region rows, real descriptors
#   python vm_sim.py dclaims  # D(claims_len) sweep, synthetic claims
#
# Established (see adj9/rev/vm_activation.md):
#   * the interpreter draws EXACTLY 8 rand values per run = ONE 0x2e6
#     whiten-cycle activation (4 pair-XOR units = the 16-B wire header);
#   * D_init = 0: nothing draws between srand(time(NULL)) (0x12cbc0) and the
#     interpreter call (0x12d39c) -- the header sits at stream positions 0..7;
#   * D(claims_len) = 8, CONSTANT (claims 4 B .. 2048 B tested, all rows);
#   * the body (44 dwords) and the region per-call words (W0/X/tile/d2/d4)
#     are descriptor-merge/fill outputs, NOT rand draws.
# ---------------------------------------------------------------------------
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]      # descriptor enumeration order
HERE = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'


def full_program(descs, seed, maxsteps=40_000_000):
    """Run the full interpreter program on real descriptor data.

    descs: list of 11 (len_dw, tag, data_bytes) in VA_ORDER.
    seed:  the srand() seed (the signing second).
    Returns dict(status, steps, nrand, activations, header_words, f0_words).
    """
    import json as _json
    import struct as _struct
    from fin_vm2 import FinEx
    ex = FinEx(seed, descs)
    status = ex.run(max_steps=maxsteps)
    f0 = {}
    for (sva, n, v) in ex.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:      # output sink F0
            f0[n & 0xFFFFFFFF] = v & 0xFFFFFFFF
    words = [f0.get(i) for i in range(48)]
    return {'status': status, 'steps': ex.steps, 'nrand': ex.nrand,
            'activations': ex.nrand / 8.0,
            'header_words': words[:4], 'f0_words': words}


def descs_from_row(r):
    """Build the 11-descriptor list (VA_ORDER) from an all_signings row."""
    out = []
    for k in VA_ORDER:
        hx = r['d10'] if k == 10 else ('' if k in (1, 3) else r['d%d' % k])
        data = bytes.fromhex(hx)
        out.append((len(data) // 4, 0, data))
    return out


def _main_full():
    import struct as _struct
    import json as _json
    rows = _json.load(open(HERE + '/all_signings.json'))
    ph3 = _json.load(open(HERE + '/pair_h3.json'))
    print('row | claims_B | status | steps | nrand | act(0x2e6) | blob48/48')
    for i, r in enumerate(rows):
        blob = bytes.fromhex(ph3[i]['blob']) if i < len(ph3) else None
        sec = ph3[i]['second'] if i < len(ph3) else 1789240512
        res = full_program(descs_from_row(r), sec)
        hit = 0
        if blob:
            tgt = [_struct.unpack_from('>I', blob, 4 * k)[0] for k in range(48)]
            hit = sum(1 for k in range(48) if res['f0_words'][k] == tgt[k])
        print('%3d | %8d | %s | %8d | %5d | %10.2f | %9s' %
              (i, len(r['d10']) // 2, res['status'], res['steps'], res['nrand'],
               res['activations'], ('%d/48' % hit) if blob else 'n/a'))


def _main_dclaims():
    import struct as _struct
    import json as _json
    rows = _json.load(open(HERE + '/all_signings.json'))
    base = rows[7]
    for n in (1, 4, 90, 512):
        descs = []
        for k in VA_ORDER:
            if k == 10:
                data = bytes(((i2 * 7 + 13) & 0xFF) for i2 in range(4 * n))
            elif k == 7:
                data = _struct.pack('>I', 4 * n)
            elif k in (1, 3):
                data = b''
            else:
                data = bytes.fromhex(base['d%d' % k])
            descs.append((len(data) // 4, 0, data))
        res = full_program(descs, 1789240512)
        print('claims=%-5d B -> status=%s steps=%-9d nrand=%d activations=%.2f'
              % (4 * n, res['status'], res['steps'], res['nrand'], res['activations']))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'full':
        _main_full()
    elif len(sys.argv) > 1 and sys.argv[1] == 'dclaims':
        _main_dclaims()
    else:
        sim()
