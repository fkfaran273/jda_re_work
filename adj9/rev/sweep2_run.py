import subprocess, sys
CANDS = """fb1a8296 00000000 00000001 0000001e 0000001f 00000021 00000023 00000024
00000168 00000400 00000364 ffffffff fb1a8297 fb1a8296dead 0000001f00000000 96021afb
01040000 00100400 40001000 0000000a 00000064 00000100 00010000""".split()
PY = r'C:\Python314\python.exe'
procs = {}
for c in CANDS:
    hex8 = (c[:8]).rjust(8, '0')[-8:]
    p = subprocess.Popen([PY, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\sweep2_one.py', hex8],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    procs[p] = hex8
    running = [p for p in procs if p.poll() is None]
    while len(running) >= 8:
        done = [p for p in running if p.poll() is not None]
        for p in done:
            print(p.communicate()[0].strip(), flush=True)
            del procs[p]
        running = [p for p in procs if p.poll() is None]
        if len(running) >= 8:
            import time
            time.sleep(5)
            for p in list(running):
                if p.poll() is not None:
                    print(p.communicate()[0].strip(), flush=True)
                    del procs[p]
            running = [p for p in procs if p.poll() is None]
for p in list(procs):
    print(p.communicate()[0].strip(), flush=True)
print('SWEEP-DONE', flush=True)
