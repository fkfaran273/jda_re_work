# so_scan.py - find the desc10 emission-order key array inside libsigner.so .rodata
import struct, re, sys
SO = r'C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so'
data = open(SO, 'rb').read()
print('so size:', len(data))

# extract printable ascii strings with offsets
strs = []
cur = bytearray()
start = 0
for i, b in enumerate(data):
    if 32 <= b < 127:
        if not cur:
            start = i
        cur.append(b)
    else:
        if len(cur) >= 5:
            strs.append((start, cur.decode('latin1')))
        cur = bytearray()
if len(cur) >= 5:
    strs.append((start, cur.decode('latin1')))
print('total strings:', len(strs))

# locate each known key; find the densest cluster window containing >= 20 of our keys
KEYS = ['adj_verification','android_uuid','api_level','app_token','app_version','created_at',
        'device_name','device_type','environment','gps_adid','gps_adid_src','hardware_name',
        'installed_at','os_build','os_name','os_version','package_name','adj_signing_id',
        'updated_at','activity_kind','client_sdk','headers_id','native_version',
        'store_name_from_system','initiating_package_name','session_count','tracking_enabled',
        'gps_adid_attempt','foreground','connectivity_type','needs_response_details',
        'attribution_deeplink','ui_mode','payload_timer','wait_time','wait_total',
        'retry_count','first_error','last_error','queue_size','sent_at','device_manufacturer',
        'display_width','display_height','screen_density','screen_format','screen_size','language',
        'cpu_type','offline_mode_enabled']
soff = {}
for off, s in strs:
    if s in KEYS and s not in soff:
        soff[s] = off
print('found %d of %d keys in .so strings' % (len(soff), len(KEYS)))
missing = [k for k in KEYS if k not in soff]
print('missing from .so:', missing)
seq = sorted(soff.items(), key=lambda kv: kv[1])
print('=== .rodata offset order of keys ===')
prev = None
for k, off in seq:
    gap = '' if prev is None else ' +%d' % (off - prev)
    print('  %#x %-26s%s' % (off, k, gap))
    prev = off
# density check: are all found keys within one window?
offs = sorted(off for _, off in soff.items())
if offs:
    span = offs[-1] - offs[0]
    print('key window: %#x..%#x span=%d bytes' % (offs[0], offs[-1], span))
