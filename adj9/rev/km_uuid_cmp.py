# km_uuid_cmp.py - the decisive test: map security level -> km_uuid -> owning
# process. keystore_cli_v2 can only mint keys at "strongbox" or "tee"; the app's
# key2 carries km_uuid 000...001. If the tee/strongbox probes land on a DIFFERENT
# km_uuid, then key2 is NOT a TEE key and its HMAC must be computed outside the
# vendor keymaster HAL; if they match key2's uuid, the HAL is the place to hook.
import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
NEW = os.path.join(HERE, 'ks_after.sqlite')
OLD = os.path.join(HERE, 'ks.sqlite')


def uu(b):
    if b is None:
        return '-'
    return bytes(b).hex()


def load(path):
    con = sqlite3.connect(path)
    cur = con.cursor()
    rows = list(cur.execute(
        'select id, key_type, domain, namespace, alias, state, km_uuid from keyentry'))
    out = {}
    for (kid, kt, dom, ns, alias, st, km) in rows:
        a = alias.decode('latin1') if isinstance(alias, bytes) else str(alias)
        out[kid] = dict(kid=kid, type=kt, dom=dom, ns=ns, alias=a, state=st, km=km)
    con.close()
    return out


new = load(NEW)
old = load(OLD)
print('entries: new=%d old=%d' % (len(new), len(old)))
print()
print('=== NEW keyentries (created since ks.sqlite) ===')
added = [k for k in new if k not in old]
for k in added:
    r = new[k]
    print('  id=%-21s ns=%-6s alias=%-28s km_uuid=%s'
          % (r['kid'], r['ns'], r['alias'][:28], uu(r['km'])))
if not added:
    print('  (none)')
print()
print('=== km_uuid histogram (all live entries) ===')
h = {}
for r in new.values():
    h.setdefault(uu(r['km']), []).append(r)
for u, rs in sorted(h.items(), key=lambda kv: -len(kv[1])):
    nss = sorted({r['ns'] for r in rs})
    print('  km_uuid=%s  count=%-3d namespaces=%s' % (u, len(rs), nss[:8]))
print()
print('=== the app (namespace 10350) ===')
for r in new.values():
    if str(r['ns']) == '10350':
        print('  alias=%-24s km_uuid=%s state=%s' % (r['alias'][:24], uu(r['km']), r['state']))
print()
print('=== shell probes (namespace 2000) ===')
for r in new.values():
    if str(r['ns']) == '2000':
        print('  alias=%-28s km_uuid=%s' % (r['alias'][:28], uu(r['km'])))