"""Launch the adj7 device-oracle proxy.

  python run_oracle.py [port]

Phone: WiFi proxy -> this PC:<port>; open http://mitm.it on the phone and
install the Android CA if HTTPS fails; then click the link, install the app
from Play, and open it.  Every adjust call is re-signed with OUR signer and
logged to oracle_log.jsonl (the attribution verdict is printed live).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888


def main():
    from mitmproxy.tools.main import mitmdump  # noqa: E402
    sys.argv = ["mitmdump",
                "-s", os.path.join(HERE, "adj7_oracle.py"),
                "-p", str(PORT),
                "--set", "block_global=false",
                "--set", "confdir=" + os.path.join(HERE, "confdir"),
                # intercept ONLY adjust; every other host tunnels through
                # UNTOUCHED (no pinning breakage, no CA install needed on
                # the phone for any other host; adjust uses the Fiddler
                # root the phone already trusts)
                "--set", "allow_hosts=^app\\.adjust\\.com(:|$)",
                "--ssl-insecure"]
    print("adj7 oracle listening on :%d  (log: %s)" % (PORT, os.path.join(HERE, "oracle_log.jsonl")))
    mitmdump()


if __name__ == "__main__":
    main()
