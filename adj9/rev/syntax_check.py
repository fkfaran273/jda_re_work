# syntax_check.py - parse every script touched this session.
import ast
import os

REV = r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev'
FS = ['adj9_forge.py', 'adj9_full_chain.py', 'desc10_law.py', 'h_crack.py',
      'desc10_consistency.py', 'verify_law_blob.py', 'verify_map_blob2.py',
      'material_vs_captured.py', 'descs_layout.py', 'replica_recipe.py',
      'unsigned_test.py', 'run_funnel.py', 'mint_session_chain.py',
      'query_audit.py', 'dev_verdict.py', 'facts.py', 'fix_tasks.py',
      'desc10_scan.py', 'desc10_click.py', 'show_mint4.py', 'send_mint4.py']
bad = []
for f in FS:
    p = os.path.join(REV, f)
    if not os.path.exists(p):
        bad.append((f, 'MISSING'))
        continue
    try:
        ast.parse(open(p, encoding='utf-8').read())
    except Exception as e:
        bad.append((f, '%s: %s' % (type(e).__name__, str(e)[:60])))
print('checked %d files' % len(FS))
print('syntax errors:', bad if bad else 'NONE')
