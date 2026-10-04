"""mitmdump addon: log every request (url + body) to capture.jsonl."""
import json
import time


def request(flow):
    try:
        rec = {
            "ts": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "headers": dict(flow.request.headers),
            "body": flow.request.get_text(strict=False) or "",
        }
        with open(r"C:\Users\Apps\Downloads\com.penti.app\adj8\cap\capture.jsonl",
                  "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception as e:
        with open(r"C:\Users\Apps\Downloads\com.penti.app\adj8\cap\capture_err.log",
                  "a") as f:
            f.write(repr(e) + "\n")
