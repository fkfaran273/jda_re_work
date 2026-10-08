"""List every oversized blob that would block the push.

GitHub rejects any blob > 100 MB.  We also flag the 50-100 MB band, which pushes
but bloats the repo irreversibly (history keeps every version forever).
"""
import subprocess, sys, os

os.chdir(r"C:\Users\Apps\Downloads\com.penti.app")

def run(*a):
    return subprocess.run(["git"] + list(a), capture_output=True, text=True).stdout

# every path in the index (what a push would send), with its size
out = run("ls-files", "-s")
entries = []
for line in out.splitlines():
    parts = line.split("\t", 1)
    if len(parts) != 2:
        continue
    sha = parts[0].split()[1]
    entries.append((parts[1], sha))

sizes = {}
for path, sha in entries:
    s = run("cat-file", "-s", sha).strip()
    if s.isdigit():
        sizes[path] = int(s)

# which of those are already on the remote?
remote = set(run("ls-tree", "-r", "--name-only", "origin/main").splitlines())

big = [(p, s) for p, s in sizes.items() if s > 50 * 1024 * 1024]
big.sort(key=lambda t: -t[1])

BLOCK = 100 * 1024 * 1024
print("%-58s %10s  %s" % ("path", "MB", "status"))
print("-" * 88)
newblock, existed = [], []
for p, s in big:
    mb = s / 1024.0 / 1024.0
    on_remote = p in remote
    tag = "ALREADY ON REMOTE" if on_remote else ("BLOCKS PUSH" if s > BLOCK else "pushes, bloats repo")
    print("%-58s %10.1f  %s" % (p[:58], mb, tag))
    if not on_remote:
        (newblock if s > BLOCK else existed).append((p, s))

print()
print("blocking (new, >100MB): %d files, %.1f GB" % (len(newblock), sum(s for _, s in newblock) / 1e9))
print("optional (new, 50-100MB): %d files, %.1f GB" % (len(existed), sum(s for _, s in existed) / 1e9))
