#!/usr/bin/env python3
"""Dump the ZCode CLI session transcript (prior Z.ai-authored work on adj9)."""
import sqlite3, json, sys, os

DB = r'C:\Users\Apps\.zcode\cli\db\db.sqlite'
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'zcode_session.txt')

c = sqlite3.connect(DB)
c.row_factory = sqlite3.Row

# message data -> role, message id -> parts
msgs = {}
for r in c.execute('select id,session_id,time_created,sequence,data from message order by time_created, sequence'):
    try:
        d = json.loads(r['data'])
    except Exception:
        d = {}
    msgs[r['id']] = (r['time_created'], d.get('role', '?'), d)

parts = {}
for r in c.execute('select message_id,sequence,data from part order by time_created, sequence'):
    try:
        d = json.loads(r['data'])
    except Exception:
        d = {'type': 'raw', 'text': r['data']}
    parts.setdefault(r['message_id'], []).append((r['sequence'], d))

lines = []
for mid, (tc, role, md) in sorted(msgs.items(), key=lambda kv: (kv[1][0], kv[0])):
    lines.append('\n' + '=' * 100)
    lines.append(f'### [{role}] t={tc} msg={mid}')
    lines.append('=' * 100)
    for seq, d in parts.get(mid, []):
        t = d.get('type')
        if t == 'text':
            lines.append(d.get('text', ''))
        elif t == 'reasoning':
            lines.append('-- reasoning --')
            lines.append((d.get('text') or '')[:4000])
        elif t == 'tool':
            tool = d.get('tool') or d.get('name') or '?'
            state = d.get('state', {})
            inp = state.get('input') or d.get('input')
            out = state.get('output') or d.get('output')
            lines.append(f'-- TOOL {tool} --')
            if inp is not None:
                s = json.dumps(inp, ensure_ascii=False) if not isinstance(inp, str) else inp
                lines.append('  IN : ' + s[:1500])
            if out is not None:
                s = json.dumps(out, ensure_ascii=False) if not isinstance(out, str) else out
                lines.append('  OUT: ' + s[:2500])
        elif t == 'step-start' or t == 'step-finish':
            pass
        else:
            lines.append(f'-- part type={t} --')
            lines.append(json.dumps(d, ensure_ascii=False)[:1500])

txt = '\n'.join(lines)
with open(OUT, 'w', encoding='utf-8') as f:
    f.write(txt)
print('wrote', OUT, len(txt), 'chars')
