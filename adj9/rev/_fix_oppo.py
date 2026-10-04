import json, uuid, ast
gaid = '6f821a21-a132-4b59-bea8-b5232702f881'
auid = str(uuid.uuid4())
ref = 'adjust_reftag=cI3Z6U1zErFsw&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic'
t = open('py_struct_test.py', encoding='utf-8').read()
t = t.replace('cline_struct1', 'cline_oppo1')
t = t.replace('gps = str(uuid.uuid4())', chr(103) + 'ps = ' + repr(gaid))
t = t.replace('auid = str(uuid.uuid4())', chr(97) + 'uid = ' + repr(auid))
t = t.replace('moto g42', 'CPH2629')
t = t.replace('motorola', 'OPPO')
t = t.replace('os_version**: 12', 'os_version**: 15')
t = t.replace('api_level**: 31', 'api_level**: 35')
t = t.replace('Android 12; moto g42 Build/S2SE32.28-28-4', 'Android 15; CPH2629')
t = t.replace('py_struct_result.json', 'py_oppo_result.json')
t = t.replace('offline_mode_enabled**: 0', 'offline_mode_enabled**: 0, mcc: 405, mnc: 910')
open('py_oppo_struct.py', 'w', encoding='utf-8').write(t)
ast.parse(t)
print('written + syntax OK, len=%d' % len(t))
