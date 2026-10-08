"""Print the actual LAST LIVE hunch run's signer config + a sample of one
sourced claim, to show exactly what values went on the wire. No more
overwriting output files mid-stream."""
import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
for p in ('last_run_hunch.json',):
    if os.path.exists(os.path.join(HERE, p)):
        d = json.load(open(os.path.join(HERE, p)))
        print('###', p)
        for k in ('gaid', 'adid', 'reftag', 'click_second', 'session_ask_in'):
            if k in d: print('  %-16s %s' % (k, str(d[k])[:100]))
        a = d.get('attribution') or {}
        for k in ('tracker_token', 'network', 'engagement_time', 'installed_at'):
            print('  attr.%-12s %s' % (k, a.get(k)))
