"""brute-event.py -- for the event-capture's record b, enumerate every
"claims" string built from (present wire keys in pool order) with /
 without act/client_sdk/endpoint injected at every plausibly-admissible
 position, and every allowed set of key drops/adds for secret_id and
 app_secret, to hunt the inconsistency."""
import itertools, json, re, sys

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import adj7_pure as sg

rec_b = "80FB85767B695CED99CE39E8FE367E345A29829FFA538E570D6FB7E1F7618A54"
nonce_hex = "0e7e996625146a274159a65c"
cert = b'C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF'
nonce = bytes.fromhex(nonce_hex)

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\hanaf_map.json"))
event = next(c for c in D['captures'] if c['kind_or_endpoint_hint'].startswith('event'))
nsign = event['nsign_map']

# build the value vector the same way we do know-correct for session
split = sg.CLAIM_POOL.index('session_count')
profile, tail, block2 = (sg.CLAIM_POOL[:split], sg.CLAIM_POOL[split:-2],
                         sg.CLAIM_POOL[-2:])

def claims(m):
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, '')]
    parts.append(sg.ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, '')]
    parts += [str(m[k]) for k in block2 if m.get(k) not in (None, '')]
    return ''.join(parts).encode('latin1')

# the nSession/m Session currently known-match yields True
# for event we brute a few "things":
variants = []
base_names = list(nsign.keys())
for drop_keys in (
    [k for k in ['subsession_count', 'wait_time', 'enqueue_size',
                 'session_length', 'seq', 'event_token', 'event_count',
                 'callback_params', 'sent_at', 'offline_mode_enabled',
                 'screen_density', 'ui_mode', 'gps_adid_attempt']]
    for k in []):
    pass
# simpler grid
names_with_unknown = ['activity_kind', 'client_sdk', 'endpoint']
extras = [
    ('bare', []),
    ('act', ['activity_kind']),
    ('cs',  ['client_sdk']),
    ('ep',  ['endpoint']),
    ('act+cs', ['activity_kind', 'client_sdk']),
    ('act+ep', ['activity_kind', 'endpoint']),
    ('cs+ep',  ['client_sdk', 'endpoint']),
    ('act+cs+ep', ['activity_kind', 'client_sdk', 'endpoint']),
]
for label, keys_dropped in []:
    pass

for name, keep in extras:
    m = dict(nsign)
    for must in ['activity_kind', 'client_sdk']:
        if must in m and must not in keep:
            m.pop(must)
    msg = cert + nonce + sg.SHA0_HEX.encode() + claims(m)
    H = sg.sha256_iv0(msg).hex().upper()
    print(name, 'act=', m.get('activity_kind'), ' cs=', m.get('client_sdk'),
          ' ep=', m.get('endpoint'), '=>  match:', H == rec_b, '|  len:', len(claims(m)))

# Now a much GIANT brute: pool keys with/without every key
# of the event's wire keys plus/minus block2-like + endpoint.
# Use it to find right set + 1300000 position.
wire_keys = [k for k in nsign.keys() if k not in
             ('activity_kind', 'client_sdk', 'endpoint',
              'adj_signing_id', 'algorithm', 'headers_id', 'native_version')]
all_map_keys = wire_keys
print("\nkey list with the nsign map (in order):")
print(all_map_keys)
