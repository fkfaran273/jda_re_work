import io

lines = io.open("run_funnel.py", encoding="utf-8").readlines()

new = (
    "# ============ PASTE HERE (used when no CLI args given) ============\n"
    "# 1) LINK: paste the tracker click link. BOTH forms work:\n"
    "#    - template with placeholders: ...&click_id={click_id}&idfa={sub3}&...\n"
    "#      -> {click_id} AND {sub3} are both replaced with the install GAID\n"
    "#    - already-clicked link (real GAID inside): ...&click_id=<GAID>&idfa=<GAID>\n"
    "#      -> if REFERRER_PASTED is set, the click is NOT fired again\n"
    "LINK = \"https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id={click_id}&idfa={sub3}&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp\"\n"
    "\n"
    "# 2) DEVICE_JSON: paste the device-data JSON (raw JSON, or a file path).\n"
    "DEVICE_JSON = \"\"\"\"\"\"\n"
    "\n"
    "# 3) PIN_GPS: the GAID / install identity.\n"
    "#    \"\" -> taken from the LINK (idfa=/gps_adid=/click_id=) if present, else fresh.\n"
    "PIN_GPS = \"\"\n"
    "\n"
    "# 4) REFERRER_PASTED: set ONLY if the link was already clicked and you do NOT\n"
    "#    want a new click fired. When set, the click step is SKIPPED and this\n"
    "#    referrer string is used directly.\n"
    "REFERRER_PASTED = \"\"\n"
    "\n"
)
out = lines[:39] + [new] + lines[56:]
io.open("run_funnel.py", "w", encoding="utf-8").write("".join(out))
print("paste section replaced")
