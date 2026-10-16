import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
import run_install_ios as R

# genuine nirio field lists (sid 38 session, 33 click, 39 attribution)
GEN = {
 'session': ['bundle_id','primary_dedupe_token','app_version','foreground','installed_at','device_name','app_version_short','retry_count','needs_response_details','attribution_deeplink','session_count','os_name','send_in_background_enabled','enqueue_size','sent_at','idfv','app_token','os_version','environment','started_at','created_at','offline_mode_enabled','device_type','att_status','idfa'],
 'click': ['bundle_id','source','primary_dedupe_token','app_version','foreground','installed_at','device_name','app_version_short','needs_response_details','attribution_deeplink','attribution_token','session_count','os_name','send_in_background_enabled','session_length','sent_at','time_spent','app_token','environment','os_version','subsession_count','started_at','idfv','created_at','offline_mode_enabled','device_type','att_status','idfa'],
 'attr': ['bundle_id','primary_dedupe_token','initiated_by','app_version','installed_at','device_name','app_version_short','needs_response_details','attribution_deeplink','send_in_background_enabled','os_name','sent_at','idfv','app_token','os_version','environment','started_at','created_at','device_type','att_status','idfa'],
}
R._IDFA = R.new_idfa(); R._IDFV = R.new_idfv() if hasattr(R,'new_idfv') else str(__import__('uuid').uuid4()).upper()
import time
sec = int(time.time())
try:
    S = R.build_session(R._IDFA, sec)
except Exception as e:
    S = {}
    print('build_session sig err', e)
print('genuine session:', len(GEN['session']), '| ours:', len(S))
print('missing in ours:', [k for k in GEN['session'] if k not in S])
print('extra in ours  :', [k for k in S if k not in GEN['session']])
