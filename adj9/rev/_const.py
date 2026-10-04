"""_const.py — is anything in our signature a per-DEVICE constant that should
be per-SIGNING?  S = V ^ (pid<<16); if pid is fixed and V is derived from the
second, S varies.  But the mint must also be checked for other constants."""
import sys, struct
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod

print('DEFAULT_PID =', M.DEFAULT_PID, hex(M.DEFAULT_PID))
print()
# S for several consecutive seconds -- does it vary?
print('S per second (pid fixed):')
for s in (1789390100, 1789390101, 1789390102, 1789390103):
    V = M.make_V_consistent(s, 928)
    S = (V ^ ((M.DEFAULT_PID & 0xFFFF) << 16)) & 0xFFFFFFFF
    print('   sec=%d  V=0x%08x  S=0x%08x' % (s, V, S))
print()
# the constants baked into every mint
print('Per-mint constants:')
print('   D8 =', bytes.fromhex('bffffffffffffd1f0007000000000000').hex(), '(cert-independent)')
print('   D9 =', bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd').hex(), '(APK cert SHA-1 -- device-INDEPENDENT, same for all installs of this APK)')
