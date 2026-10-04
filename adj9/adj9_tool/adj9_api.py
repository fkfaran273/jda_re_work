"""adj9_api.py -- the Adjust API calls, separate from the signature.

Given a claims map this module builds the wire params, signs them with
adj9_signer, and sends the request.  Three endpoints:

    session(params)     POST /session       first app-open after install
    sdk_click(params)   POST /sdk_click     the install attribution itself
    attribution(params) GET  /attribution   the verdict poll

Everything device-specific comes from `device_profile.json` (default: the
moto g42 the research was done on).  Pass `profile=` to override.

Two transports:
    "pc"      -- this machine (default; simplest)
    "device"  -- `adb shell curl`, so the request leaves from the phone's IP
                 and TLS stack.  Set serial= to pick the device.
"""
import datetime
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_signer as S

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_TEMPLATES = json.load(open(os.path.join(HERE, "_base_templates.json")))
PROFILE_PATH = os.path.join(HERE, "device_profile.json")

BASE_URL = "https://app.adjust.com"
APP_TOKEN = "jut9tib0eeps"          # com.penti.app
PACKAGE = "com.penti.app"
ORGANIC_TOKEN = "wy7261z"           # the known Organic tracker_token

# Keys that describe the DEVICE; they come from the profile, never a template.
DEVICE_KEYS = {"api_level", "os_version", "device_name", "device_manufacturer",
               "hardware_name", "os_build", "app_version", "install_version",
               "language", "display_width", "display_height",
               "screen_density", "mcc", "mnc", "no_sim"}


def _tz_from_label(label):
    """"+0530" / "-0400" -> minutes east of UTC."""
    s = str(label).strip()
    sign = -1 if s.startswith("-") else 1
    digits = s.lstrip("+-")
    return sign * (int(digits[:2]) * 60 + int(digits[2:4]))


def _auto_profile_from_dump(dump):
    """Turn a raw device-info JSON dump (any device) into an adj9 profile.

    Recognises the common keys emitted by device-info tools and maps them onto
    the DEV/UA/OFF_* fields the signer needs.  Best-effort: anything it cannot
    find falls back to the shipped moto g42 defaults so the run still works.
    """
    base = load_profile(PROFILE_PATH)  # defaults / fallback
    g = lambda *keys, default=None: next(
        (dump[k] for k in keys if k in dump and dump[k] not in (None, "")), default)

    model = g("model", "device_name", "product", default="moto g42")
    brand = g("manufacturer", "brand", default="motorola")
    build = g("build", "display", "os_build", default=base["DEV"]["os_build"])
    sdk = str(g("sdk", "api_level", default=base["DEV"]["api_level"]))
    osver = str(g("os_version", default=base["DEV"]["os_version"]))
    tz_label = g("timezone", "local_tz", default=base["OFF_LABEL"])
    if not str(tz_label).startswith(("+", "-")):
        tz_label = base["OFF_LABEL"]

    dev = dict(base["DEV"])
    dev.update({
        "api_level": sdk,
        "os_version": osver,
        "device_name": model,
        "device_manufacturer": brand,
        "hardware_name": g("hardware", "display", "os_build", "build",
                           default=build),
        "os_build": build,
    })
    if "locale" in dump and isinstance(dump["locale"], dict):
        dev["language"] = dump["locale"].get("language", dev.get("language"))
    dm = dump.get("display_metrics") or {}
    if dm.get("xpx"):
        dev["display_width"] = str(dm["xpx"])
    if dm.get("ypx"):
        dev["display_height"] = str(dm["ypx"])
    # The wire value is Adjust's own low/medium/high bucket computed from the
    # raw dpi -- NOT the cosmetic resource label ("xhdpi" and friends), which
    # is only meaningful to Android's resource resolver.
    raw_dpi = g("dpi", "density_dpi_raw")
    if raw_dpi not in (None, ""):
        try:
            dpi = int(float(raw_dpi))
        except (TypeError, ValueError):
            dpi = None
        if dpi is not None:
            dev["screen_density"] = ("low" if dpi < 140 else
                                     "medium" if dpi <= 200 else "high")
    elif g("screen_density_wire"):
        dev["screen_density"] = str(g("screen_density_wire"))
    # mcc/mnc are never on the wire for this app.
    dev["no_sim"] = True
    dev.pop("mcc", None)
    dev.pop("mnc", None)

    raw_ua = g("User-Agent", "user_agent")
    # The device's real browser UA is what a genuine CLICK presents as; keep it
    # for the click.  The SDK's own API calls use a Dalvik UA.
    click_ua = raw_ua or base.get("CLICK_UA") or base["UA"]
    ua = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
          % (osver, model, build))

    return {
        "DEV": dev,
        "UA": ua,
        "CLICK_UA": click_ua,
        "OFF_MINUTES": _tz_from_label(tz_label),
        "OFF_LABEL": tz_label if str(tz_label).startswith(("+", "-"))
                     else base["OFF_LABEL"],
        "ADD_IDFA": base.get("ADD_IDFA", False),
        "device_json_fields": {
            "sdk": sdk, "os_version": osver, "model": model, "brand": brand,
            "mainboard": g("mainboard", "name", "product", default=build),
            "build": build,
            "display_metrics.xpx": str(dm.get("xpx", "")),
            "display_metrics.ypx": str(dm.get("ypx", "")),
            "display_metrics.density_dpi": str(dm.get("density_dpi", "")),
        },
        "_auto_built_from": "raw device dump",
    }


def load_profile(path=None):
    """Load a profile.  Accepts:
         - None                -> the shipped device_profile.json
         - a path to a JSON file
         - a path to a RAW DEVICE DUMP  -> auto-converted to a profile
         - an already-built profile dict
         - a JSON string (a profile OR a raw device dump)
    """
    if isinstance(path, dict):
        p = dict(path)
    elif isinstance(path, str) and path.lstrip().startswith("{"):
        p = json.loads(path)  # a JSON string was handed to us
    else:
        fp = path or PROFILE_PATH
        p = json.load(open(fp, encoding="utf-8"))

    # A raw device dump has no DEV/UA keys -> build a profile from it.
    if "DEV" not in p or "UA" not in p:
        p = _auto_profile_from_dump(p)
    # The shipped profile carries a stale CTIT from a confounded experiment and
    # is kept for reference only; callers supply CTIT explicitly.
    p.pop("ctit", None)
    return p


class Api(object):
    """The three Adjust endpoints, signed and sent."""

    def __init__(self, profile=None, transport="pc", serial=None, timeout=120):
        self.profile = profile or load_profile()
        self.DEV = dict(self.profile["DEV"])
        self.UA = self.profile["UA"]
        self.OFF_MINUTES = self.profile["OFF_MINUTES"]
        self.OFF_LABEL = self.profile["OFF_LABEL"]
        self.ADD_IDFA = self.profile.get("ADD_IDFA", False)
        self.transport = transport
        self.serial = serial
        self.timeout = timeout
        self.MINT_SKEW = -2              # sign slightly in the past

    # -- helpers ----------------------------------------------------------
    def fmt(self, ts, ms):
        """Wire timestamp in the profile's timezone."""
        dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
              + datetime.timedelta(minutes=self.OFF_MINUTES))
        # strftime takes ONE format string, so the offset label is appended
        # after formatting -- otherwise it is parsed as part of the format.
        return (dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % ms
                + "Z" + self.OFF_LABEL).encode()
    def _dev_fields(self, include_install_version=False):
        d = dict(self.DEV)
        d.pop("no_sim", None)
        # The real app never puts SIM network codes on the wire.
        d.pop("mcc", None)
        d.pop("mnc", None)
        if not include_install_version:
            d.pop("install_version", None)
        return d

    def _base(self, template):
        p = dict(BASE_TEMPLATES[template])
        p.update(self._dev_fields(include_install_version=(template == "S2P")))
        return p

    def _sign(self, params, kind, second, V, pid, max_steps):
        val = S.claims_from_wire(params, kind)
        kw = {"max_steps": max_steps} if max_steps else {}
        blob, info = S.mint_blob(val, kind, second=second, V=V, pid=pid, **kw)
        return blob, info, val

    def _V_for(self, params, sec, V):
        """The region V, consistent with the stamps this request transmits.

        A server can recompute the region by enumerating tv_usec inside the
        [created_at, sent_at] window, so V must name that same second and a
        usec inside that window.  Passing V explicitly overrides this.
        """
        if V is not None:
            return V
        c_ms = int(params["created_at"][20:23])
        s_ms = int(params["sent_at"][20:23])
        return S.make_V_in_window(c_ms, s_ms, sec=sec)

    # -- transport --------------------------------------------------------
    def _send_pc(self, url, params, auth, method):
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError
        headers = {"Client-SDK": S.CLIENT_SDK, "User-Agent": self.UA,
                   "Authorization": auth}
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        full = url
        body = None
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
        else:
            full = url + ("&" if "?" in url else "?") \
                + urllib.parse.urlencode(params)
        req = Request(full, data=body, headers=headers, method=method)
        try:
            r = urlopen(req, timeout=self.timeout)
            return r.getcode(), r.read().decode("utf-8", "replace")
        except HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def _send_device(self, url, params, auth, method):
        # adb shell concatenates args into ONE remote command, so every part is
        # shlex-quoted -- otherwise '&' in the body is re-parsed by the shell.
        parts = ["curl", "-s", "-S", "-k", "--max-time", "45", "-X", method,
                 "-w", "\n###HTTP:%{http_code}",
                 "-H", "Client-SDK: " + S.CLIENT_SDK,
                 "-H", "User-Agent: " + self.UA,
                 "-H", "Authorization: " + auth]
        if method == "POST":
            parts += ["-H", "Content-Type: application/x-www-form-urlencoded",
                      url, "--data-raw", urllib.parse.urlencode(params)]
        else:
            sep = "&" if "?" in url else "?"
            parts += [url + sep + urllib.parse.urlencode(params)]
        remote = " ".join(shlex.quote(p) for p in parts)
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += ["shell", remote]
        p = subprocess.run(cmd, capture_output=True, timeout=self.timeout)
        out = p.stdout.decode("utf-8", "replace")
        code = "ERR"
        if "###HTTP:" in out:
            out, code = out.rsplit("###HTTP:", 1)
            try:
                code = int(code.strip())
            except ValueError:
                pass
        if not out.strip() and p.stderr:
            return "ERR", p.stderr.decode("utf-8", "replace")[:200]
        return code, out

    def send(self, path, params, blob, method="POST"):
        auth = S.auth_header(blob)
        url = BASE_URL + path
        if self.transport == "device":
            return self._send_device(url, params, auth, method)
        return self._send_pc(url, params, auth, method)

    # -- endpoints --------------------------------------------------------
    # Region/stamp/seed consistency: the VM is seeded with `sec` (the signing
    # second), so created_at/sent_at must be stamped at `sec` and the region V
    # must be built from `sec` too.  Stamping at `sec - 1` while seeding with
    # `sec` makes the region irreconcilable with the wire stamps — a detectable
    # tell that forces the Organic default.  (Mirrors mint_pipeline.make_V_consistent.)
    def session(self, gps_adid, android_uuid, installed_at=None, second=None,
                V=None, pid=None, max_steps=None, verbose=True):
        sec = second if second is not None else int(time.time()) + self.MINT_SKEW
        insd = installed_at or self.fmt(sec - 170, 774).decode()
        p = self._base("S1P")
        p.update({"gps_adid": gps_adid, "android_uuid": android_uuid,
                  "created_at": self.fmt(sec, 928).decode(),
                  "sent_at": self.fmt(sec, 942).decode(),
                  "installed_at": insd, "updated_at": insd})
        blob, info, _ = self._sign(p, "session", sec,
                                   self._V_for(p, sec, V), pid, max_steps)
        if verbose:
            self._log("session", info)
        return self.send("/session", p, blob)

    def sdk_click(self, gps_adid, android_uuid, referrer, click_time,
                  install_begin_time, installed_at, second=None, V=None,
                  pid=None, max_steps=None, verbose=True):
        sec = second if second is not None else int(time.time()) + self.MINT_SKEW
        p = self._base("S2P")
        p.update({"gps_adid": gps_adid, "android_uuid": android_uuid,
                  "created_at": self.fmt(sec, 961).decode(),
                  "sent_at": self.fmt(sec, 970).decode(),
                  "installed_at": installed_at, "updated_at": installed_at,
                  "referrer": referrer, "source": "install_referrer",
                  "referrer_api": "google",
                  "click_time": self.fmt(click_time, 0).decode(),
                  "click_time_server": self.fmt(click_time - 2, 0).decode(),
                  "install_begin_time": self.fmt(install_begin_time, 0).decode(),
                  "install_begin_time_server":
                      self.fmt(install_begin_time - 2, 0).decode()})
        if self.ADD_IDFA:
            p["idfa"] = gps_adid
        blob, info, _ = self._sign(p, "click", sec,
                                   self._V_for(p, sec, V), pid, max_steps)
        if verbose:
            self._log("sdk_click", info)
        return self.send("/sdk_click", p, blob)

    def attribution(self, gps_adid, android_uuid, initiated_by="backend",
                    second=None, V=None, pid=None, max_steps=None,
                    verbose=True):
        sec = second if second is not None else int(time.time()) + self.MINT_SKEW
        d = self._dev_fields()
        p = {"initiated_by": initiated_by, "gps_adid_attempt": "1",
             "api_level": d["api_level"], "app_version": d["app_version"],
             "app_token": APP_TOKEN, "os_version": d["os_version"],
             "created_at": self.fmt(sec, 666).decode(),
             "device_type": "phone", "gps_adid": gps_adid, "foreground": "1",
             "android_uuid": android_uuid,
             "sent_at": self.fmt(sec, 696).decode(),
             "offline_mode_enabled": "0", "device_name": d["device_name"],
             "environment": "production", "needs_response_details": "1",
             "attribution_deeplink": "1", "package_name": "com.penti.app",
             "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
             "tracking_enabled": "1"}
        if self.ADD_IDFA:
            p["idfa"] = gps_adid
        blob, info, _ = self._sign(p, "attribution", sec,
                                   self._V_for(p, sec, V), pid, max_steps)
        if verbose:
            self._log("attribution", info)
        return self.send("/attribution", p, blob, method="GET")

    def _log(self, kind, info):
        print("[mint] %s status=%s #10=%dB/%dB"
              % (kind, info["status"], info["desc10_padded"],
                 info["desc10_unpadded"]), flush=True)


def read_verdict(body):
    """The oracle.  Organic == the zero engagement timestamp."""
    try:
        j = json.loads(body)
    except Exception:
        return None
    a = j.get("attribution") or j
    eng = a.get("engagement_time")
    tok = a.get("tracker_token")
    if tok is None:
        return None
    organic = eng in (None, "", "0001-01-01T00:00:00Z")
    return {"token": tok, "network": a.get("network"),
            "engagement_time": eng, "installed_at": a.get("installed_at"),
            "organic": organic,
            "verdict": "ORGANIC" if organic else "NON-ORGANIC"}


if __name__ == "__main__":
    import uuid
    api = Api()
    gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
    t = int(time.time())
    api.session(gps, auid, installed_at=api.fmt(t - 170, 774).decode())
    api.sdk_click(gps, auid, "utm_source=google-play&utm_medium=organic",
                  t - 220, t - 10, api.fmt(t - 170, 774).decode())
    code, body = api.attribution(gps, auid)
    print(code, read_verdict(body))
