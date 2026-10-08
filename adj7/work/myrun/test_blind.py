import os
os.environ['FUNNEL_PROXY'] = 'http://127.0.0.1:8899'
os.environ['FUNNEL_BLIND'] = '1'
import run_hunch as H
st, b = H.call('GET', '/robots.txt', {}, 'x')
print('blind relay GET ->', st, len(b))
