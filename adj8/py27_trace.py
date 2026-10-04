import sys, traceback
import adj8_pure_py27 as S

def wrap(cls, name):
    orig = getattr(cls, name)
    def f(self, *a, **k):
        try:
            return orig(self, *a, **k)
        except Exception:
            print("!! in %s:" % name)
            traceback.print_exc(file=sys.stdout)
            raise
    setattr(cls, name, f)

for m in ("hook_code", "hook_code2", "plt_dispatch", "jni_dispatch", "jni_call",
          "call_method", "alloc"):
    if hasattr(S.Emu, m):
        wrap(S.Emu, m)

sys.argv = ["adj8_pure_py27.py", "--selftest"]
S.self_test()
