"""_k49.py — why 49 click keys instead of 47?"""
import sys, json
sys.path.insert(0, '.')
import nonorg_redrive as R
gc = R.load('2_c.txt')
GOLD = json.load(open('golden_saz.json'))
S2P = GOLD['s2']['params']
DEV = {"api_level":"35","os_version":"15","device_name":"23090RA98I",
       "device_manufacturer":"Xiaomi","hardware_name":"zircon",
       "os_build":"AP3A.240905.015.A2","app_version":"3.13.9",
       "install_version":"3.13.9","language":"tr","mcc":"286","mnc":"01",
       "display_width":"1220","display_height":"2712","screen_density":"xxhdpi"}
cp = {k:v for k,v in S2P.items() if k not in ('store_name_from_system','initiating_package_name','mcc','mnc')}
print('base s2 minus 3:', len(cp))
print('genuine non-organic click:', len(gc))
print('extra vs genuine:', sorted(set(cp)-set(gc)))
print('missing vs genuine:', sorted(set(gc)-set(cp)))
