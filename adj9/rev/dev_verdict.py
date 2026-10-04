# dev_verdict.py - pull the device's AdjustAttribution / ActivityState and print the
# printable strings (the authoritative verdict, per TASKS hard rule).
import re
import subprocess

FILES = {
    'AdjustAttribution': '/data/data/com.penti.app/files/AdjustAttribution',
    'AdjustIoActivityState': '/data/data/com.penti.app/files/AdjustIoActivityState',
}


def sh(cmd):
    p = subprocess.run(['adb', 'shell', cmd], capture_output=True)
    return p.stdout


for name, path in FILES.items():
    raw = sh("/debug_ramdisk/su -c 'cat %s'" % path)
    toks = re.findall(rb'[ -~]{4,}', raw)
    print('=== %s (%d B) ===' % (name, len(raw)))
    for t in toks:
        s = t.decode('ascii', 'replace')
        if '"tracker_token"' in s:
            import json as _j
            i = s.find('{\"tracker_token\"')
            j = s.rfind('}')
            try:
                d = _j.loads(s[i:j + 1])
                print('   FULL ATTRIBUTION JSON:')
                for k, v in d.items():
                    print('      %-22s %s' % (k, v))
            except Exception as e:
                print('   raw:', s[:400], e)
        elif s.startswith('{') and ('gps_adid' in s or 'app_token' in s
                                    or 'activity_kind' in s):
            print('   MAP/JSON blob (%d chars):' % len(s))
            print('     ', s[:1500])
