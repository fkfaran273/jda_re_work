import io, json

t = io.open("run_funnel.py", encoding="utf-8").read()

# 1) the user's already-clicked link
user_link = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
             "&creative=penti_generic&click_id=80970d76-1b90-4e28-97cc-a6e5cd55f690"
             "&idfa=80970d76-1b90-4e28-97cc-a6e5cd55f690"
             "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D80970d76-1b90-4e28-97cc-a6e5cd55f690%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp"
             "&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D80970d76-1b90-4e28-97cc-a6e5cd55f690%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")

# 2) the user's Redmi device JSON (compact)
dev = {
    "kernel": "15", "locale": {"country": "IN", "language": "en"},
    "ram": {"available": "5401", "shown": "8112"},
    "os_incremental": "OS2.0.3.0.VNUINXM", "bluetooth": "3.0", "hardware": "",
    "imei": "868663035562624", "cpu_core": "7", "private_ip": "10.0.211.23",
    "device_type": "phone", "timezone": "+0530", "serial": "232427507a2a1454",
    "mnc": "908", "android_id": "b9b26e146de12319", "cpu_arch": "aarch64",
    "display_metrics": {"ypx": "1080", "screen_layout_name": "large",
        "screen_layout_format": "long", "xpx": "2312", "ydp": 440.098,
        "xdp": 439.962, "aspect_ratio": "14:6", "density_dpi": "xxhdpi"},
    "last_rebooted_at": 1789928380318, "network_band": "LTE", "cpu_abi2": "",
    "User-Agent": "Mozilla/5.0 (Linux; Android 15; 2406ERN9CI Build/AQ3A.240912.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/152.0.7977.42 Mobile Safari/537.36",
    "cpu_frequency": {"max": "1958.0", "min": "499.0"}, "os_version": "15",
    "build": "AQ3A.240912.001", "manufacturer": "Xiaomi",
    "product": "breeze_in", "brand": "Redmi", "screen_size": "5.8",
    "mcc": "405", "device_id": "80970d76-1b90-4e28-97cc-a6e5cd55f690",
    "adid": "80970d76-1b90-4e28-97cc-a6e5cd55f690",
    "fingerprint": "Redmi/breeze_in/breeze:15/AQ3A.240912.001/OS2.0.3.0.VNUINXM:user/release-keys",
    "device": "breeze", "sdk": "35", "mainboard": "breeze",
    "country": "India", "cpu_abi": "arm64-v8a", "network": "WiFi",
    "carrier": "Vi India", "os_codename": "REL", "model": "2406ERN9CI",
    "resolution": "1080x2312", "dpi": "440",
}

# 3) the user's referrer (already-clicked; click will be skipped)
user_ref = ("adjust_reftag=cxaOf09vQrBHs&utm_source=VKM+Digital+Yeni"
            "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")

# surgical replaces in the paste section
import re
t = re.sub(r"^LINK = \".*\"$", 'LINK = "' + user_link + '"', t, count=1, flags=re.M)
t = re.sub(r'^DEVICE_JSON = """.*?"""$',
           'DEVICE_JSON = """' + json.dumps(dev) + '"""', t, count=1, flags=re.M | re.S)
t = re.sub(r"^PIN_GPS = \".*\"$", 'PIN_GPS = ""', t, count=1, flags=re.M)
t = re.sub(r"^REFERRER_PASTED = \".*\"$",
           'REFERRER_PASTED = "' + user_ref + '"', t, count=1, flags=re.M)

io.open("run_funnel.py", "w", encoding="utf-8").write(t)
print("paste section filled with the user's link/device/referrer")
