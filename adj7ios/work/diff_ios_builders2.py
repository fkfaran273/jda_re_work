import os, sys, time, uuid
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import run_install_ios as R

GEN = {
 'session': 'bundle_id primary_dedupe_token app_version foreground installed_at device_name app_version_short retry_count needs_response_details attribution_deeplink session_count os_name send_in_background_enabled enqueue_size sent_at idfv app_token os_version environment started_at created_at offline_mode_enabled device_type att_status idfa'.split(),
 'click': 'bundle_id source primary_dedupe_token app_version foreground installed_at device_name app_version_short needs_response_details attribution_deeplink attribution_token session_count os_name send_in_background_enabled session_length sent_at time_spent app_token environment os_version subsession_count started_at idfv created_at offline_mode_enabled device_type att_status idfa'.split(),
 'attr': 'bundle_id primary_dedupe_token initiated_by app_version installed_at device_name app_version_short needs_response_details attribution_deeplink send_in_background_enabled os_name sent_at idfv app_token os_version environment started_at created_at device_type att_status idfa'.split(),
}
R._IDFA = R.new_idfa()
R._IDFV = R.new_idfv()
sec = int(time.time())
S = R.build_session_request(sec)
A = R.build_attribution_request(sec)
C = R._common(sec)
print('session: genuine', len(GEN['session']), 'ours', len(S))
print('  MISSING:', [k for k in GEN['session'] if k not in S])
print('  EXTRA  :', [k for k in S if k not in GEN['session']])
print('attr: genuine', len(GEN['attr']), 'ours', len(A))
print('  MISSING:', [k for k in GEN['attr'] if k not in A])
print('  EXTRA  :', [k for k in A if k not in GEN['attr']])
print('tps builder keys:', sorted(R.build_tps_request(sec).keys())[:8], '...')
