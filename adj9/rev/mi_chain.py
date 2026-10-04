# mi_chain.py - the user's scenario: the link was ALREADY CLICKED on the real
# device (reftag cA1DXYdvcrG5k came from that click). NO click fired here.
# Just the Python call chain from PC with the given GAID + referrer:
#   /session -> /sdk_click(referrer) -> /attribution
# with the PROVEN adj9 signature maker, profiled as that Xiaomi device.
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as fc
import device_funnel as df

OUT = os.path.join(HERE, "mi_chain_result.json")

# --- the clicked device (user-supplied DEVICE DATA + clicked link) ---
GPS = "274418fe-880e-4739-9a7f-1ee44c61ab7d"
REFERRER = ("adjust_reftag=cA1DXYdvcrG5k&utm_source=VKM+Digital+Yeni"
            "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")

# --- profile the maker as the clicked device (Mi M2012K11AI, Android 13) ---
MI = {"api_level": "33", "os_version": "13",
      "device_name": "M2012K11AI", "device_manufacturer": "Xiaomi",
      "hardware_name": "aliothin", "os_build": "TKQ1.220829.002",
      "app_version": "3.13.9", "install_version": "3.13.9",
      "language": "en", "mcc": "405", "mnc": "849",
      "display_width": "1080", "display_height": "2320",
      "screen_density": "xxhigh"}
MI_UA = "Dalvik/2.1.0 (Linux; U; Android 13; M2012K11AI Build/TKQ1.220829.002)"

fc.DEV, fc.UA = dict(MI), MI_UA
df.fc.DEV, df.fc.UA = dict(MI), MI_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"     # device tz IST
df.OFF_MINUTES = 330

# route through the validated funnel proxy (same egress as before)
df.install_proxy("http://127.0.0.1:8888")
os.environ["ADJ_INSECURE"] = "1"

# the real click happened shortly before this run (device-side)
df.CLICK_EPOCH = int(time.time()) - 300

# --- the full Python chain from PC (session -> sdk_click -> attribution) ---
auid = "b3f1c2d4-0000-4000-8000-%012x" % (int(time.time()) & 0xFFFFFFFFFFFF)
rec = df.full(GPS, REFERRER, auid, click_first=False)
rec["gps"] = GPS
rec["auid"] = auid
rec["referrer"] = REFERRER
json.dump(rec, open(OUT, "w"), indent=1)
print("saved", OUT, flush=True)
