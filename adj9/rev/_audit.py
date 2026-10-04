"""_audit.py — full field audit: our Redmi 23090RA98I bodies vs the user's
device data AND vs the genuine non-organic record."""
import json, sys
sys.path.insert(0, '.')
import nonorg_redrive as R

gs = R.load('1_c.txt'); gc = R.load('2_c.txt')
print('=== GENUINE non-organic device fields (what Adjust actually sends) ===')
for k in ('device_name','device_manufacturer','hardware_name','os_build','os_name',
          'os_version','api_level','language','mcc','mnc','display_width',
          'display_height','screen_density','screen_size','screen_format',
          'cpu_type','device_type','app_version','install_version',
          'connectivity_type','network_band','carrier','gps_adid_src'):
    for src, nm in ((gs,'sess'), (gc,'click')):
        if k in src:
            print('  %-24s [%s] = %s' % (k, nm, src[k]))
print()
print('=== our Redmi profile as configured in _run4.py ===')
DEV = {"api_level": "35", "os_version": "15", "device_name": "23090RA98I",
       "device_manufacturer": "Xiaomi", "hardware_name": "zircon",
       "os_build": "AP3A.240905.015.A2", "app_version": "3.13.9",
       "install_version": "3.13.9", "language": "tr", "mcc": "286",
       "mnc": "01", "display_width": "1220", "display_height": "2712",
       "screen_density": "xxhdpi"}
for k, v in DEV.items():
    print('  %-24s = %s' % (k, v))
print()
print('=== screen_density vocabulary: what values does Adjust actually use? ===')
import os, re
b = open('../device/adj9_capture_full.log','rb').read().decode('utf-8','replace')
print('  device capture values:', sorted(set(re.findall(r'screen_density=([^,&}]+)', b))))
print()
print('=== golden_saz base values for the fields we inherit ===')
GOLD = json.load(open('golden_saz.json'))
for k in ('screen_density','screen_size','screen_format','cpu_type','hardware_name'):
    print('  %-20s s1=%-12s s2=%s' % (k, GOLD['s1']['params'].get(k), GOLD['s2']['params'].get(k)))
