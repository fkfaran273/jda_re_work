import json, urllib.parse
d = json.load(open('nirioiosauto_08Sep_ios_CT_adjust.json'))
for r in d:
    print('##### sid', r['sid'], r['method'], r['url'][:90])
    if r['method'] == 'GET':
        q = r['url'].split('?', 1)[1] if '?' in r['url'] else ''
        for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
            print('   %-26s %s' % (k, v[:90]))
    else:
        b = r.get('body')
        if isinstance(b, dict):
            for k, v in b.items():
                print('   %-26s %s' % (k, str(v)[:90]))
        else:
            print('   body:', str(b)[:120])
    print('   status:', r.get('status'))
    resp = r.get('response')
    if isinstance(resp, dict):
        print('   resp:', json.dumps(resp)[:220])
    elif resp:
        print('   resp:', str(resp)[:220])
