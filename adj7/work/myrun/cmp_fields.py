import urllib.parse, os
HERE = os.path.dirname(os.path.abspath(__file__))
H = os.path.join(HERE, 'saz_hunch_new', 'raw')
# our last live hunch run: is there a saz for it? check saz_live which is hanaf.
# reconstruct ours from last_run_hunch.json instead: we have no saz for run_hunch.
# So: print the GENUINE field-level timing shape for rows 29/30/32 to recheck.
for n, kind in [(29, 'session'), (30, 'sdk_click'), (32, 'attribution')]:
    t = open(os.path.join(H, '%02d_c.txt' % n), encoding='utf-8', errors='replace', newline='').read()
    h, _, b = t.partition('\r\n\r\n')
    f = dict(urllib.parse.parse_qsl(b.strip(), keep_blank_values=True)) if n != 32 else dict(urllib.parse.parse_qsl(t.split(' ', 2)[1].split('?', 1)[1].rsplit(' ', 1)[0], keep_blank_values=True))
    print('##### genuine', kind)
    for k in ('created_at', 'sent_at', 'installed_at', 'updated_at', 'click_time', 'click_time_server', 'install_begin_time', 'install_begin_time_server', 'wait_total', 'session_length', 'time_spent', 'enqueue_size', 'session_count', 'retry_count', 'last_error', 'first_error', 'wait_time', 'offline_mode_enabled', 'foreground', 'tracking_enabled', 'google_play_instant', 'source', 'referrer_api', 'gps_adid_src', 'needs_response_details', 'attribution_deeplink', 'ui_mode', 'subsession_count', 'session_length'):
        if k in f:
            print('  %-28s %s' % (k, f[k]))
    print('  keys:', len(f))
