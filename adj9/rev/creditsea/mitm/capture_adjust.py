"""mitm addon: capture all requests to app.adjust.com and sdk_click endpoints"""
import json
from mitmproxy import http

CAPTURED = []

def request(flow: http.HTTPFlow) -> pass_ := None:
    pass

def response(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url
    if "adjust.com" in url:
        entry = {
            "method": flow.request.method,
            "url": url,
            "headers": dict(flow.request.headers),
            "content": flow.request.get_text()[:3000] if flow.request.content else "",
            "status": flow.response.status_code if flow.response else 0,
            "response_body": flow.response.get_text()[:2000] if flow.response and flow.response.content else "",
        }
        CAPTURED.append(entry)
        with open("adjust_traffic.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"[ADJUST] {flow.request.method} {url[:100]} -> {entry['status']}")
