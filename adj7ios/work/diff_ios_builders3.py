import os, sys, time, uuid
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import run_install_ios as R

GEN = {
 'session': 'bundle_id primary_dedupe_token app_version foreground installed_at device_name app_version_short retry_count needs_response_details attribution_deeplink session_count os_name send_in_background_enabled enqueue_size sent_at idfv app_token os_version environment started_at created_at offline_mode_enabled device_type att_status idfa'.split(),
 'attr': 'bundle_id primary_dedupe_token initiated_by app_version installed_at device_name app_version_short needs_response_details attribution_deeplink send_in_background_enabled os_name sent_at idfv app_token os_version environment started_at created_at device_type att_status idfa'.split(),
}
R._IDFA = R.new_idfa()
R._IDFV = R.new_idfv()
R._DEDUPE = R.new_dedupe()
R._STARTED = int(time.time()) - 1000
R._INSTALL = int(time.time()) - 100
sec = int(time.time())
S = R.build_session_request(sec)
A = R.build_attribution_request(sec)
T = R.build_tps_request(sec)
for name, built, gen in (('session', S, GEN['session']), ('attr', A, GEN['attr'])):
    print('%-8s genuine=%d ours=%d' % (name, len(gen), len(built)))
    miss = [k for k in gen if k not in built]
    extra = [k for k in built if k not in gen]
    print('   MISSING:', miss if miss else 'none')
    print('   EXTRA  :', extra if extra else 'none')
print('tps keys:', sorted(T.keys()))
