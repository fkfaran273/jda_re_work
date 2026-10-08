"""browser_click.py -- fire the tracker link through the REAL installed
Chrome (genuine browser TLS/fingerprint, the way the winning device click
looks) and hand the reftag + server Date to the funnel.

  python browser_click.py "<url>" [--fill-gaid <gaid>]

Prints:  REFTAG=<referrer string>   CLICK_SEC=<adjust Date epoch>
"""
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright


def main():
    url = sys.argv[1]
    result = {"reftag": None, "click_sec": None}
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True,
                                    args=["--disable-blink-features=AutomationControlled"])
        ctx = browser.new_context(user_agent=(
            "Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"),
            locale="en-IN", viewport={"width": 412, "height": 915},
            is_mobile=True, has_touch=True)
        page = ctx.new_page()

        def on_response(r):
            if "app.adjust.com" in r.url and result["click_sec"] is None:
                d = r.header_value("date") if r.headers else None
                if d:
                    import email.utils
                    result["click_sec"] = int(
                        email.utils.parsedate_to_datetime(d).timestamp())

        def on_request(r):
            u = r.url
            if u.startswith("market://") or u.startswith("intent://"):
                q = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(u).query, keep_blank_values=True)
                if "referrer" in q:
                    result["reftag"] = q["referrer"][0]

        page.on("response", on_response)
        page.on("request", on_request)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception:
            pass
        # the market:// hop kills navigation; poll for the reftag
        t0 = time.time()
        while result["reftag"] is None and time.time() - t0 < 20:
            page.wait_for_timeout(500)
        browser.close()
    print("REFTAG=%s" % (result["reftag"] or "",))
    print("CLICK_SEC=%s" % (result["click_sec"] or "",))


if __name__ == "__main__":
    main()
