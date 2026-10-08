"""Capture the GENUINE phone click chain: log every HTTP flow (host, URL,
headers, body, redirect) to click_flows.jsonl.

Run:  python run_click_capture.py [port]
Phone: adb shell settings put global http_proxy <pc-ip>:<port>
Then open the mobpine link in the phone's Chrome.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else 8888
except ValueError:
    PORT = 8888
OUT = os.path.join(HERE, "click_flows.jsonl")


class ClickCapture:
    def load(self, loader):
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": "addon-load"}) + "\n")

    def request(self, flow):
        try:
            rec = {
                "t": "req",
                "host": flow.request.pretty_host,
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "body": flow.request.get_text(strict=False) or "",
            }
            with open(OUT, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception as e:
            try:
                with open(OUT, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"t": "req-err", "err": repr(e)}) + "\n")
            except Exception:
                pass

    def response(self, flow):
        try:
            rec = {
                "t": "resp",
                "host": flow.request.pretty_host,
                "url": flow.request.pretty_url,
                "status": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "body": (flow.response.get_text(strict=False) or "")[:4000],
            }
            with open(OUT, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception as e:
            sys.stderr.write("resp log err %r\n" % (e,))


addons = [ClickCapture()]

if __name__ == "__main__":
    from mitmproxy.tools.main import mitmdump
    sys.argv = ["mitmdump",
                "-s", os.path.join(HERE, "click_capture.py"),
                "-p", str(PORT),
                "--set", "block_global=false",
                "--set", "confdir=" + os.path.join(
                    HERE, "..", "..", "adj7", "oracle", "confdir"),
                "--ssl-insecure"]
    print("click capture proxy on :%d -> %s" % (PORT, OUT))
    mitmdump()
