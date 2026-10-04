# desc10_extract.py - exact full extraction of the two desc10 runs in the EMIT trace.
import json, struct

DEV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\device'
REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
d = json.load(open(DEV + r'\whcap_hits7.json', encoding='utf-8'))
evs = [e for e in d if e.get('tag') == 'emit']
words = [int(e['val'], 16) for e in evs]

def extract(head):
    out = bytearray()
    i = head
    while i < len(words):
        out += struct.pack('>I', words[i])
        i += 1
        if b'\x00' in struct.pack('>I', words[i - 1]):
            z = out.find(b'\x00')
            return bytes(out[:z]), i - 1
    return bytes(out), i

s, se = extract(55)
c, ce = extract(22327)
print('SESSION desc10: %d B, ends in dword %d' % (len(s), se))
print('CLICK   desc10: %d B, ends in dword %d' % (len(c), ce))
D = json.load(open(REV + r'\fin_descs.json', encoding='utf-8'))
g10 = bytes.fromhex([x for x in D['descs'] if x['build_idx'] == 10][0]['data_hex'])
print('session == fin_descs golden:', s == g10, '| fin_descs golden len', len(g10))
print()
print('SESSION:'); print(s.decode('latin1')); print()
print('CLICK  :'); print(c.decode('latin1')); print()
json.dump({'session': s.decode('latin1'), 'click': c.decode('latin1')},
          open(REV + r'\desc10_runs.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

# also the 3rd run (28718) - verify it repeats session
t, _ = extract(28718)
print('3rd run == session golden:', t == g10, '| len', len(t))
