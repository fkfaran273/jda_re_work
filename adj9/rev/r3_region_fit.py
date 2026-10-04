"""r3_region_fit.py - does the golden per-call region sit in a Random3(second)
stream?  Random3 IS Bionic random()/srand() (BSD TYPE_3, additive feedback):
  - rand() = random() = full 31-bit draw (NO >>1 truncation unlike glibc)
  - srand(seed) reseeds with the 31-word Park-Miller expansion + 310 warmup draws
So the golden W dwords (<= 0x7fffffff?) CAN be single rand() draws.

Test: for the golden signing second S=1789240512, generate Random3(S) stream
(~200 draws) and look for [W0, W1] = [0x13271271, 0xB7D0992B] (W1 > RAND_MAX? no:
0xB7D0992B = 3083901227 > 2^31-1 = 2147483647, so W1 needs 2 draws or an XOR mix;
W0 = 321327729 fits one draw). Also test consecutive-pair XORs, since the 16-B
header itself is built as 4x{PUSH rand; PUSH rand; XOR; EMIT}.

The decisive cross-check: SAME (map, second) => IDENTICAL region (slice 116)
is exactly what srand(second)+fixed-draw-count predicts.
"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3

S = 1789240512
W0, W1 = 0x13271271, 0xB7D0992B
C1, C2, C3 = 0xDB50F44C, 0xB63798CC, 0xDAB7F51A
D2 = 0xFB1A8296
D4W = [0x00100400, 0x04144000, 0x8000C440, 0x88104C05,
       0x0025C852, 0xCC6E00B1, 0x01E76C80, 0x427BF58E]

R = Random3(S)
stream = [R.next() for _ in range(400)]
print("golden second S=%d" % S)
print("W0=0x%08x in stream: %s" % (W0, [i for i, x in enumerate(stream) if x == W0][:4]))
print("D2=0x%08x in stream: %s" % (D2, [i for i, x in enumerate(stream) if x == D2][:4]))
print("C1=0x%08x C2=0x%08x C3=0x%08x in stream: %s %s %s"
      % (C1, C2, C3,
         [i for i, x in enumerate(stream) if x == C1][:4],
         [i for i, x in enumerate(stream) if x == C2][:4],
         [i for i, x in enumerate(stream) if x == C3][:4]))
for t, nm in ((D4W[0], "d4w0"), (D4W[1], "d4w1"), (D4W[2], "d4w2")):
    print("%s=0x%08x in stream: %s"
          % (nm, t, [i for i, x in enumerate(stream) if x == t][:4]))
print("W1=0x%08x (>RAND_MAX, needs pair): single-draw hits: %s"
      % (W1, [i for i, x in enumerate(stream) if x == W1][:4]))
# pair-XOR model: W1 = a ^ b for consecutive draws?
hit = [(i, stream[i], stream[i + 1])
       for i in range(len(stream) - 1)
       if (stream[i] ^ stream[i + 1]) & 0xFFFFFFFF == W1]
print("W1 as consecutive-pair XOR: %s" % hit[:4])
# C words as consecutive-pair XOR?
for c, nm in ((C1, "C1"), (C2, "C2"), (C3, "C3")):
    h = [i for i in range(len(stream) - 1)
         if (stream[i] ^ stream[i + 1]) & 0xFFFFFFFF == c]
    print("%s=0x%08x as pair-XOR: %s" % (nm, c, h[:4]))
# D2 as pair-XOR?
h = [i for i in range(len(stream) - 1)
     if (stream[i] ^ stream[i + 1]) & 0xFFFFFFFF == D2]
print("D2=0x%08x as pair-XOR: %s" % (D2, h[:4]))
print("done")
