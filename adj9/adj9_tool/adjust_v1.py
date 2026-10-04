import json
from datetime import datetime, timezone
import uuid
import time
import random
import util
import adj9_signer
import urllib
import urllib.parse
import urllib.parse as urlparse
import requests
import collections

ACTIVITY_UNKNOWN = "unknown"
ACTIVITY_SESSION = "session"
ACTIVITY_EVENT = "event"
ACTIVITY_CLICK = "click"
ACTIVITY_ATTRIBUTION = "attribution"
ACTIVITY_INFO = "info"
MEASUREMENT_CONSENT = "measurement_consent"
SUBSCRIPTION = "subscription"
AD_REVENUE = "ad_revenue"
THIRD_PARTY_SHARING = "third_party_sharing"

METHOD_GET = "get"
METHOD_POST = "post"
METHOD_HEAD = "head"

# The installer the Play Store reports; both session fields name it.
DEFAULT_STORE = "com.android.vending"


def _cmp(a, b):
    """Python 3 removed cmp(); this is the same three-way comparison."""
    return (a > b) - (a < b)


def _sdk_version(var):
    """'android5.7.0' -> (5, 7, 0).  The campaign's sdk string may or may not
    carry the 'android' prefix, so the prefix is stripped only if present."""
    return tuple(int(part) for part in str(var).split("android", 1)[-1].split("."))


def built_cmp(var1, var2):
    """
        cmp(var1, var2) -> integer

        Return negative if var1<var2, zero if var1==var2, positive if var1>var2.
    """
    var1 = _sdk_version(var1)
    var2 = _sdk_version(var2)
    l1, l2 = list(var1), list(var2)
    for i in range(min(len(l1), len(l2))):
        if _cmp(l1[i], l2[i]) != 0:
            return _cmp(l1[i], l2[i])
    return _cmp(len(l1), len(l2))


class AdjHelper(object):
    def __init__(self):
        pass

    @staticmethod
    def gzip_compress(__inp):
        from io import BytesIO as StringIO
        import gzip
        out = StringIO()
        with gzip.GzipFile(fileobj=out, mode="w") as __f:
            __f.write(__inp)
        return out.getvalue()

    @staticmethod
    def adj3_sign(__map, activity_kind, package_name, adj_port=None, allowed_activity_kind=["all"]):
        """This Method of ADJ IS Deprecated"""
        return {"auth": None}


class SessionAttributes(object):
    SESSION_INTERVAL = 30 * 60  # in Seconds
    SUB_SESSION_INTERVAL = 1  # in Seconds

    def __init__(self, activity_state):
        self.event_count = activity_state.get('event_count', 0)
        self.sub_session_count = activity_state.get('sub_session_count', 1)
        self.session_count = activity_state.get('session_count', 0)
        self.session_length = activity_state.get('session_length', 0)
        self.time_spent = activity_state.get('time_spent', 0)
        self.last_activity = activity_state.get('last_activity', time.time())
        self.last_interval = -1

    def save_activity_state(self):
        self.update_activity_state(time.time())
        additional_time = random.randint(100, 300)
        return {
            "session_count": self.session_count,
            "sub_session_count": self.sub_session_count,
            "last_activity": self.last_activity + additional_time,
            "event_count": self.event_count,
            "session_length": self.session_length + additional_time,
            "time_spent": self.time_spent + additional_time,
        }

    def process_session(self):
        """
        Call this method if app reopened
        :return:
        """
        now = time.time()
        last_interval = now - self.last_activity

        if last_interval < 0:
            self.last_activity = now

        elif last_interval > self.SESSION_INTERVAL:
            # self.track_new_session(now)
            pass

        elif last_interval > self.SUB_SESSION_INTERVAL:
            self.sub_session_count += 1
            self.session_length += int(last_interval)
            self.last_activity = now

    def reset(self, now):
        self.sub_session_count = 1
        self.session_length = 0
        self.time_spent = 0
        self.last_activity = now
        self.last_interval = -1

    def update_activity_state(self, now):
        last_interval = int(now - self.last_activity)
        if last_interval <= self.SESSION_INTERVAL:
            self.last_activity = now
            if last_interval >= 0:
                self.session_length += last_interval
                self.time_spent += last_interval


#######################################################################################
# CTIT Module Implementation and There Utility Methods.
class CTIT(object):
    """This class is for Accessing keys present in CTIT Module.
        It Takes arguments  app_data, device_data, app_size, os="android"(default for now).

        Attributes
        ----------
        app_data : dict
            To save app related info.

        device_data : dict
            Dictionary which contains device related info.

        app_size : float
            app_size present in campaign_data.

        os : str
            default value of os is "android" for now.


        Methods
        -------
        click_time()
            returns click_time

        install_complete_time()
            returns install_complete_time

        download_end_time()
            returns download_end_time

        download_begin_time()
            returns download_begin_time
    """

    # How long the click->install and click->download-start gaps are.  These
    # are the numbers the genuine capture shows: the click lands, the download
    # starts a few seconds later, and the install completes a little after.
    DEFAULT_CTIT = 6.0
    DEFAULT_DOWNLOAD_BEGIN = 4.0
    DOWNLOAD_SPAN = 2.0

    def measure_install(self, app_data, device_data, app_size=None, os="android",
                        min_ctit=None):
        """Work out the four install timestamps the SDK reports.

        Replaces the old `installtimenew` module, which is not in this tree.
        Pass app_data['times'] to supply real measured times instead -- that is
        what you want after a genuine adb install, where the gap was actually
        observed rather than modelled.
        """
        if isinstance(app_size, dict):
            app_size = app_size.get('size')
        try:
            app_mb = float(app_size) if app_size else 8.0
        except (TypeError, ValueError):
            app_mb = 8.0

        # Bigger downloads take longer; ~1.5s per MB, clamped to a sane band.
        transfer = max(2.0, min(20.0, app_mb * 1.5))
        begin = float(min_ctit) if min_ctit else self.DEFAULT_DOWNLOAD_BEGIN
        begin = max(0.5, min(begin, transfer))
        ctit = max(begin + 1.0, transfer + begin * 0.5)

        now = time.time()
        t_begin = now - ctit + begin
        t_end = now - ctit + begin + self.DOWNLOAD_SPAN
        print("  modelled install: ctit=%.1fs  download %.1fs  app=%.1fMB"
              % (ctit, self.DOWNLOAD_SPAN, app_mb))
        return {
            'click_time': now - ctit,
            'download_begin_time': t_begin,
            'download_end_time': t_end,
            'install_complete_time': now,
        }

    def __init__(self, app_data, device_data, app_size, os="android", min_ctit=None):
        if "times" not in app_data:
            print("Please wait installing...")
            self.times = self.measure_install(app_data, device_data,
                                              app_size=app_size, os=os,
                                              min_ctit=min_ctit)
        else:
            self.times = app_data.get('times')

        self.time_z = device_data['timezone']
        # Hours/minutes must use integer floor division: for "+0530" the hour
        # part is 530//100 = 5 (not 530/100 = 5.3).  Using `/` inflates the
        # offset by 0.8h (1080s), which stamps created_at ~18 min into the
        # future and leaves the signature's embedded second 1080s away from
        # created_at -- a detectable tell that forces the Organic default.
        sec = (abs(int(self.time_z)) // 100) * 3600 + (abs(int(self.time_z)) % 100) * 60
        self.time_sec = (-1 if int(self.time_z) < 0 else 1) * sec

    def click_time(self):
        return self.times.get('click_time')

    def install_complete_time(self):
        return self.times.get('install_complete_time')

    def download_end_time(self):
        return self.times.get('download_end_time')

    def download_begin_time(self):
        return self.times.get('download_begin_time')

    ############################################################################################
    def get_utc_time(self, ts=None):
        if not ts:
            ts = time.time()
        ts += self.time_sec
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z' + self.time_z

    def installed_at(self):
        return self.get_utc_time(self.install_complete_time())

    def download_begin_at(self):
        return self.get_utc_time(self.download_begin_time())

    def clicked_at(self):
        return self.get_utc_time(self.click_time())

    # The *_server stamps are the backend's own clock reading of the same event,
    # and in the genuine capture that clock runs a flat 2 s behind the handset's:
    #     click_time 17:48:35.000  click_time_server 17:48:33.000
    #     install_begin 17:52:05.000  install_begin_time_server 17:52:03.000
    # A device whose clock agrees with the server to the millisecond is not a
    # thing real handsets produce -- NTP keeps them close, never identical -- so
    # emitting the two as the same value reads as synthetic.  The offset is
    # measured, not guessed: 2.0 s in both pairs of the winning capture.
    SERVER_CLOCK_SKEW = 2.0

    def clicked_at_server(self):
        return self.get_utc_time(self.click_time() - self.SERVER_CLOCK_SKEW)

    def download_begin_at_server(self):
        return self.get_utc_time(self.download_begin_time() - self.SERVER_CLOCK_SKEW)


#######################################################################################
# All keys and data related to campaign_data will be defined here.
class CampaignData(object):
    def __init__(self, campaign_data):
        self.campaign = campaign_data
        self.app_token = self.campaign.get('adjust').get('app_token')
        if not self.app_token or len(self.app_token) != 12:
            raise ValueError("Malformed App Token '%s'" % self.app_token)

        self.adjust_sdk = self.campaign.get('adjust').get('sdk')
        self.sdk = self.adjust_sdk.split("@")[1] if "@" in self.adjust_sdk else self.adjust_sdk
        if self.sdk not in [
            "android4.12.0", "android4.12.1", "android4.12.2", "android4.12.3", "android4.12.4", "android4.13.0",
            "android4.14.0", "android4.15.0", "android4.15.1", "android4.16.0", "android4.17.0", "android4.18.0",
            "android4.18.1", "android4.18.2", "android4.18.3", "android4.18.4", "android4.19.0", "android4.19.1", "android4.20.0",
            "android4.21.0", "android4.21.1", "android4.21.2", "android4.22.0", "android4.23.0", "android4.24.0",
            "android4.24.1", "android4.25.0", "android4.26.0", "android4.26.1", "android4.26.2", "android4.27.0",
            "android4.28.0", "android4.28.1", "android4.28.2", "android4.28.3", "android4.28.4", "android4.28.5",
            "android4.28.6", "android4.28.7", "android4.28.8", "android4.28.9", "android4.29.1", "android4.30.0",
            "android4.30.1", "android4.31.0", "android4.31.1", "android4.32.0", "android4.33.0", "android4.33.1", "android4.33.2",
            "android4.33.3", "android4.33.4", "android4.33.5", "android4.34.0", "android4.35.0", "android4.35.1", "android4.36.0",
            "android4.37.0", "android4.37.1", "android4.38.0", "android4.38.1", "android4.38.2", "android4.38.3", "android4.38.4", "android4.38.5",
            "android5.0.0", "android5.0.1", "android5.0.2", "android5.1.0", "android4.0.2", "android5.0.5"
        ]:
            pass

        self.secret_id = self.campaign.get('adjust').get('secret_id')
        self.secret_key = self.campaign.get('adjust').get('secret_key')
        self.s2s_auth = self.campaign.get('adjust').get('s2s_auth')
        self.adj_port = self.campaign.get('adjust').get('adj_port')
        self.adj_server = self.campaign.get('adjust').get('server')
        if isinstance(self.adj_port, dict) and self.adj_server and self.adj_server in self.adj_port:
            self.adj_port = self.adj_port.get(self.adj_server)
        if isinstance(self.adj_port, (tuple, list)):
            self.adj_port = str(random.choice(self.adj_port))
        self.algo = "adj-new" if (self.adj_server and self.adj_port) else "sha256" if (self.secret_key and self.secret_id) else None

    def from_campaign(self, key, def_val=None):
        return self.campaign.get(key, def_val)


#######################################################################################
# All keys and data related to device_data will be defined here.
class DeviceData(object):
    def __init__(self, device_data):
        self.device = device_data

    def from_device(self, key):
        return self.device.get(key)

    def device_country(self):
        return self.from_device('locale').get('country')

    def device_language(self):
        return self.from_device('locale').get('language')

    def get_vm_isa(self):
        if self.from_device('cpu_abi') == "armeabi-v7a":
            return 'arm'
        elif self.from_device('cpu_abi') == 'arm64-v8a':
            return 'arm64'

    def device_screen_layout_format(self):
        return self.from_device('display_metrics').get("screen_layout_format")

    # Android's Configuration.SCREENLAYOUT_SIZE_* codes, in order.  The dump
    # records the numeric size; the wire names it.
    SCREEN_LAYOUT_NAMES = {1: "small", 2: "normal", 3: "large", 4: "xlarge"}

    def device_screen_layout_name(self):
        return self.SCREEN_LAYOUT_NAMES.get(
            self.from_device('display_metrics').get("screen_layout_size"))

    def device_screen_density(self):
        dpi = int(self.from_device('dpi'))
        if dpi == 0:
            return None
        elif dpi < 140:
            return 'low'
        elif dpi > 200:
            return 'high'
        else:
            return 'medium'

    def device_type(self):
        screen_size = int(self.from_device('display_metrics').get("screen_layout_size"))
        if screen_size in [1, 2]:
            return "phone"
        elif screen_size in [3, 4]:
            return "tablet"
        else:
            return ""

    def network_type(self):
        net_band = self.from_device("network_band")
        return {
            "LTE": "13",
            "GSM": "16",
            "UMTS": "3",
            "CDMA": "4",
            "UNKNOWN": "0",
            "IDEN": "11",

            "MVNO": "13",  # Considering as 4G based on wireless
            "WiMAX": "13",  # Considering as 4G based on wireless
            "SCDMA": "17",  # same as TD_SCDMA TD stands for roaming
            # "5G": 0.2,
            "TD-LTE": "13"  # Same as LTE TD Stands for roaming
        }.get(str(net_band).upper(), "0")


#######################################################################################
# All keys and data related to app_data will be defined here.
class AppData(object):
    PUSH_TOKEN = "push_token"
    FB_ID = "fb_id"
    APP_SET_ID = "google_app_set_id"

    def __init__(self, app_data):
        self.app = app_data

    def from_app(self, key, def_val=None):
        return self.app.get(key, def_val)

    def def_(self, key):
        if key not in self.app:
            self.app[key] = 0

    def inc_(self, key):
        self.def_(key)
        self.app[key] += 1

    def android_uuid(self):
        if "and_uuid" not in self.app:
            self.app["and_uuid"] = str(uuid.uuid4()).lower()
        return self.app["and_uuid"]


#######################################################################################
# All Utility Methods Used and Required will be defined here.
class AdjustUtil(CTIT, CampaignData, AppData, DeviceData):
    BASE_URL_CHINA = "app.adjust.world"
    BASE_URL_EU = "app.eu.adjust.com"
    BASE_URL_INDIA = "app.adjust.net.in"
    BASE_URL_TR = "app.tr.adjust.com"
    BASE_URL_US = "app.us.adjust.com"
    BASE_URL = "app.adjust.com"

    def __init__(self, campaign_data, app_data, device_data, day=0, min_ctit=None):
        CampaignData.__init__(self, campaign_data)
        AppData.__init__(self, app_data)
        DeviceData.__init__(self, device_data)
        CTIT.__init__(self, app_data, device_data, self.from_campaign('app_size'), min_ctit=min_ctit)

        self.day = int(day)
        self.connectivity_type_str = self.get_network_type()
        self.connectivity_type = "1" if self.connectivity_type_str == "WIFI" else "0"
        self.event_buffering_enabled = "0"
        self.attribution_deeplink = "1"
        self.environment = "production"
        self.adjust_domain = self.BASE_URL
        self.needs_response_details = "1"
        self.device_known = None
        self.needs_cost = None
        self.reset_url_strategy()

    def get_network_type(self):
        """WIFI or LTE, read off the device dump.

        Replaces the missing `networkmodule`.  The dump's `network` /
        `network_band` field is what a device-info app reports; without one we
        say WIFI, which is the safer of the two (a phone that is on mobile
        data is far rarer than one that is not).
        """
        dev = self.device
        raw = str(dev.get('network') or dev.get('network_band') or 'WIFI').upper()
        if raw in ('LTE', '4G', '5G', 'UMTS', 'CDMA', 'HSPAP', 'HSPA', 'EHRPD'):
            return 'LTE'
        return 'WIFI'

    def reset_url_strategy(self):
        if built_cmp(self.sdk, "android4.24.0") >= 0:
            self.adjust_domain = {
                "IN": self.BASE_URL_INDIA,
                "CN": self.BASE_URL_CHINA,
            }.get(self.device_country(), self.BASE_URL)
        else:
            self.adjust_domain = self.BASE_URL

    ############################################################################################
    # Signature Related Method

    def get_auth(self, created_at, activity_type, source=None):
        if source and built_cmp(self.sdk, "android4.12.0") >= 0 and built_cmp(self.sdk, "android4.17.0") <= 0:
            source = None
        sdk = int(self.from_device("sdk"))
        gps_adid = self.from_device("adid")
        if sdk >= 26:  # os 8 and above
            if source:
                data1 = created_at + gps_adid + source + self.secret_key + activity_type
                headers = "created_at gps_adid source app_secret activity_kind"
            else:
                data1 = created_at + gps_adid + self.secret_key + activity_type
                headers = "created_at gps_adid app_secret activity_kind"

        else:
            if source:
                data1 = created_at + activity_type + source + self.secret_key + gps_adid
                headers = "created_at activity_kind source app_secret gps_adid"
            else:
                if sdk > 23:  # for os 7
                    data1 = str(created_at + activity_type + self.secret_key + gps_adid)
                    headers = "created_at activity_kind app_secret gps_adid"
                else:  # for os <7
                    data1 = str(created_at + self.secret_key + gps_adid + activity_type)
                    headers = "created_at app_secret gps_adid activity_kind"
        sign = util.sha256(data1)
        return 'Signature secret_id="{0}",signature="{1}",algorithm="{2}",headers="{3}"'.format(
            self.secret_id, sign, "sha256", headers
        )

    def get_adj_auth(self, _dict, activity_kind):
        """This Method of ADJ IS Deprecated"""
        return ''

    @staticmethod
    def dict_to_json(_dict, ensure_ascii=True):
        return json.dumps(_dict, separators=(",", ":"), ensure_ascii=ensure_ascii)

    # The three activity kinds the adj9 signing laws are known for.  Other
    # Adjust endpoints (event / info / revenue / third-party-sharing) have no
    # reconstructed signature and fall back to sha256 or go unsigned.
    SIGN_KINDS = {
        ACTIVITY_SESSION: "session",
        ACTIVITY_CLICK: "click",
        ACTIVITY_ATTRIBUTION: "attribution",
    }

    @staticmethod
    def _stamp_ms(stamp):
        """The millisecond-of-second inside a wire timestamp (index 20..22)."""
        return int(str(stamp)[20:23])

    def _sign_second(self, created_at):
        """The Unix second named by the created_at we are about to transmit.

        The envelope header carries this second, so it is derived from the
        stamp that goes on the wire rather than read from the clock at
        signing time.
        """
        try:
            naive = datetime.strptime(str(created_at)[:23], "%Y-%m-%dT%H:%M:%S.%f")
            epoch = int(naive.replace(tzinfo=timezone.utc).timestamp())
            return epoch - int(self.time_sec)
        except Exception:
            return int(time.time())

    def adj9_sign(self, wire_map, activity_kind):
        """Mint a local adj9 envelope for one request and return its header.

        wire_map is exactly the form map that goes on the wire -- every signed
        claim is the value Adjust will receive, so the two can never drift.

        The signing seed is fresh randomness per call, because the native
        draws it from /dev/urandom on every signing.  It travels to the
        server inside descriptor #2, so the body stays self-consistent and
        verifiable without the seed ever being predictable.
        """
        kind = self.SIGN_KINDS.get(activity_kind)
        if kind is None:
            raise ValueError("adj9 law not reconstructed for %r" % (activity_kind,))

        val = adj9_signer.claims_from_wire(wire_map, kind)
        created_at = wire_map.get("created_at")
        second = self._sign_second(created_at)

        blob, info = adj9_signer.mint_blob(val, kind, second=second)
        auth = adj9_signer.auth_header(blob)
        if len(blob) != 192:
            raise RuntimeError("adj9 envelope is %d bytes, expected 192" % len(blob))
        return auth, info

    def adj_new(self, __map, activity_kind, force_adj=False):
        auth = None
        if activity_kind in self.SIGN_KINDS:
            try:
                auth, info = self.adj9_sign(__map, activity_kind)
                print("[+] adj9 signed {} | d10={}B | steps={} | status={}".format(
                    activity_kind, info["desc10_unpadded"], info["steps"], info["status"]))
            except Exception as exc:
                message = {
                    "pkg": self.from_campaign("package_name"),
                    "err": "adj9 sign failed: %r" % (exc,), "call": activity_kind,
                }
                self.push_request_to_queue('adj_error_codes', message)
        if not auth and self.secret_id and self.secret_key:
            auth = self.get_auth(__map.get('created_at'), activity_kind)
        return {"auth": auth}

    ############################################################################################
    @staticmethod
    def push_request_to_queue(_queue_name, _message):
        try:
            print("[QUEUE:{}]  SENDING: {}".format(_queue_name, _message))
            response = requests.post(
                url="http://{}:{}/api/exchanges/%2F/amq.default/publish".format("3.249.246.145", 15672), auth=("AdjErrors", "adjErrorMails@123"),
                json={"properties": {"delivery_mode": 2}, "routing_key": _queue_name, "payload": json.dumps(_message), "payload_encoding": "string"},
                proxies={"http": None, "https": None}
            )
            if not response.json().get('routed'):
                raise Exception("Queue \"{}\" not exists!!".format(_queue_name))
            else:
                return True
        except:
            import traceback
            traceback.print_exc()
        return False

    # Other Utility Method
    def set_event_buffering_enabled(self, val):
        self.event_buffering_enabled = str(val)

    def set_fb_id(self):
        if AppData.FB_ID not in self.app:
            self.app[AppData.FB_ID] = str(uuid.uuid4()).lower()

    def set_device_known(self, val):
        self.device_known = str(val)

    def set_needs_cost(self, val):
        self.needs_cost = str(val)

    def set_push_token(self, token=None):
        if AppData.PUSH_TOKEN not in self.app:
            self.app[AppData.PUSH_TOKEN] = "{0}:APA91b{1}".format(
                util.get_random_string("google_token", 22), util.get_random_string("google_token", 134)
            ) if token is None else token
        return self.app[AppData.PUSH_TOKEN]

    def update_adjust_domain(self, domain):
        if domain in [self.BASE_URL_CHINA, self.BASE_URL_TR, self.BASE_URL_US, self.BASE_URL_INDIA, self.BASE_URL_EU,
                      self.BASE_URL]:
            self.adjust_domain = domain
        else:
            raise ValueError("Unknown Adjust Base URL!!! " + domain)

    def adjust_url(self, subdomain, protocol="https"):
        return "{0}://{1}/{2}".format(protocol, self.adjust_domain, subdomain)

    def set_appset_id(self):
        if AppData.APP_SET_ID not in self.app:
            self.app[AppData.APP_SET_ID] = str(uuid.uuid4())


#######################################################################################
# All Adjust Related Callings related Methods will be defined here.
class AdjustConfig(AdjustUtil):
    def __init__(self, campaign_data, app_data, device_data, day=0, debugger_agent=None, min_ctit=None):
        AdjustUtil.__init__(self, campaign_data, app_data, device_data, day=day, min_ctit=min_ctit)
        util.perform_campaign_data_checks(campaign_data)

        self.call_recorder = False
        self.session_check = False
        self.activity_state = SessionAttributes(self.from_app("activity_state", {}))
        self.session_time = None
        self.unique_events = set(app_data.get('unique_events', []))
        self.google_adid = None
        self.api_serv_data = {
            "agentId": debugger_agent, "package_name": campaign_data.get("package_name"), "tracker": "adjust", "device_data": device_data
        } if debugger_agent else None
        self.enable_tracking = True

    def tracking_enabled(self, _flag):
        self.enable_tracking = bool(_flag)

    def ok_with_adj(self, _log=True):
        """Signing used to be a remote service; it is now local, so the honest
        liveness check is: can we mint a valid 192-byte envelope right now?"""
        try:
            probe = {
                "created_at": self.get_utc_time(), "sent_at": self.get_utc_time(),
                "app_token": self.app_token, "app_version": self.from_campaign('app_version_name'),
                "package_name": self.from_campaign('package_name'),
            }
            auth, info = self.adj9_sign(probe, ACTIVITY_SESSION)
            print("[+] Local adj9 signer is Alive (d10={}B, {} steps)".format(
                info["desc10_unpadded"], info["steps"]))
            return True
        except Exception as exc:
            print("Local adj9 signer unavailable. {}".format(exc))
        if _log:
            message = {"camp": self.from_campaign("package_name"), "network_name": self.from_app("network_name"), "channel": self.from_app("channel"), "offer_id": self.from_app("offer_id")}
            message.update({"port": self.adj_port, "server": self.adj_server})
            self.push_request_to_queue('adj_return_false', message)
        return False

    ##################################################################################
    def __del__(self):
        self.app["activity_state"] = self.activity_state.save_activity_state()
        if self.unique_events:
            self.app["unique_events"] = list(self.unique_events)

    ######################################################################################################

    def dalvik_agent(self):
        """The Dalvik UA the SDK itself talks with.

        The genuine capture sends
        Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)
        so the build id -- not the board name -- is what goes in Build/.
        """
        dev = self.device
        model = dev.get('model') or 'device'
        build = dev.get('build') or dev.get('display') or ''
        osver = dev.get('os_version', '')
        return "Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)" % (
            osver, model, build)

    def browser_agent(self):
        """The Chrome-on-Android UA a real click from this phone presents."""
        dev = self.device
        model = dev.get('model') or 'device'
        osver = dev.get('os_version', '')
        chrome = '153.0.8010.36'
        for entry in (dev.get('User-Agent'), dev.get('user_agent')):
            if entry and 'Chrome/' in entry:
                chrome = entry.split('Chrome/', 1)[1].split(' ')[0]
                break
        return ("Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/%s Mobile Safari/537.36"
                % (osver, model, chrome))

    def headers_part(self, content_type="application/x-www-form-urlencoded"):
        h = {
            "Accept-Encoding": "gzip",
            "Client-SDK": self.adjust_sdk,
            "User-Agent": self.dalvik_agent(),
        }
        if content_type:
            h["Content-Type"] = content_type
        return h

    def data_part(self, created_at, sent_at):
        width, height = self.from_device('resolution').split('x')
        data = {
            "android_uuid": self.android_uuid(),
            "api_level": self.from_device("sdk"),
            "app_token": self.app_token,
            "app_version": self.from_campaign('app_version_name'),
            "attribution_deeplink": self.attribution_deeplink,
            "connectivity_type": self.connectivity_type,
            "cpu_type": self.from_device("cpu_abi"),
            "created_at": created_at,
            "device_manufacturer": self.from_device('manufacturer'),
            "device_name": self.from_device('model'),
            "device_type": self.device_type(),
            "display_height": height,
            "display_width": width,
            "environment": self.environment,
            "gps_adid": self.from_device('adid'),
            "hardware_name": self.from_device('display'),
            "installed_at": self.installed_at(),
            "language": self.device_language(),
            "needs_response_details": self.needs_response_details,
            "network_type": self.network_type(),
            "os_build": self.from_device('build'),
            "os_name": "android",
            "os_version": self.from_device('os_version'),
            "package_name": self.from_campaign('package_name'),
            "screen_density": self.device_screen_density(),
            "screen_format": self.device_screen_layout_format(),
            "screen_size": self.device_screen_layout_name(),
            "sent_at": sent_at,
            "session_count": str(self.activity_state.session_count or 1),
            "tracking_enabled": "1",
            "updated_at": self.installed_at(),
        }
        # country / mcc / mnc are NOT on the wire for this app: the genuine
        # captures carry no SIM fields and no country, so sending a None for
        # them is worse than omitting them.
        # event_buffering_enabled is likewise absent from every capture.
        for key in [AppData.FB_ID, AppData.PUSH_TOKEN, AppData.APP_SET_ID]:
            if key in self.app:
                data[key] = self.from_app(key)
        if self.device_known is not None:
            data["device_known"] = self.device_known
        if self.needs_cost is not None:
            data["needs_cost"] = self.needs_cost
        if self.sdk in [
            "android4.12.0", "android4.12.1", "android4.12.2", "android4.12.3", "android4.12.4", "android4.13.0",
            "android4.14.0"
        ]:
            data["vm_isa"] = self.get_vm_isa()

        if built_cmp(self.sdk, "android4.16.0") >= 0:
            data["gps_adid_src"] = "service"

            if built_cmp(self.sdk, "android4.21.2") >= 0:
                data["gps_adid_attempt"] = 1

                if built_cmp(self.sdk, "android4.28.4") >= 0:
                    data["ui_mode"] = "1"

        if built_cmp(self.sdk, "android4.30.0") >= 0:
            if data.get("network_type"):
                del data["network_type"]
        return data

    ######################################################################################################
    def adjust_session(self, u_headers={}, u_data={}, u_params={}, t1=0, t2=0, save_attr=True, force_adj=False, **kwargs):
        if not self.enable_tracking:
            print("{SESSION} Tracking Disabled")
            return {}

        url = self.adjust_url("session")
        now = time.time()
        self.activity_state.session_count += 1
        self.session_time = now

        created_at = self.get_utc_time(ts=now)
        time.sleep(random.randint(t1, t2))
        sent_at = self.get_utc_time()

        headers = self.headers_part()
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        data = self.data_part(created_at, sent_at)
        if self.activity_state.session_count > 1:
            data["last_interval"] = int(now - self.activity_state.last_activity)
            data["session_length"] = self.activity_state.session_length
            data["time_spent"] = self.activity_state.time_spent
            data["subsession_count"] = self.activity_state.sub_session_count

        # Where the package actually came from.  The app learns this from the
        # installer, so it is config, not derived state -- but the first session
        # is where it reports it, and the signature covers both fields.
        data.setdefault("store_name_from_system",
                        self.from_app("store_name_from_system", DEFAULT_STORE))
        data.setdefault("initiating_package_name",
                        self.from_app("initiating_package_name", DEFAULT_STORE))

        # The session is the only request that reports the request-queue
        # state.  With nothing queued and nothing retrying, these are the
        # values a freshly launched app reports.
        data.update({
            "enqueue_size": "0", "first_error": "0", "last_error": "0",
            "retry_count": "0", "wait_time": "0.0", "wait_total": "0.0",
            "offline_mode_enabled": "0", "foreground": "1",
        })

        for deprecatedKeys in ["callback_params", "partner_params"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)

        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(data.get('created_at'), ACTIVITY_SESSION)

        elif self.algo == "adj-new":
            data = collections.OrderedDict(data)
            auth = self.adj_new(data, ACTIVITY_SESSION, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        print(json.dumps(data))
        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        self.activity_state.reset(now)
        resp = self.network_request(request, save_attr)
        try:
            self.google_adid = json.loads(resp.get('data')).get('adid')
        except:
            pass
        return resp

    ######################################################################################################
    def adjust_event(self, u_headers={}, u_data={}, u_params={}, token=None, t1=0, t2=0, save_attr=True,
                     event_meaning=None, force_adj=False, bypass_malformed=False, **kwargs):
        if not self.enable_tracking:
            print("{EVENT} Tracking Disabled")
            return {}

        if token is None:
            raise ValueError("Missing Event Token")
        if len(token) != 6 and not bypass_malformed:
            print("Skipping Event >>{0}<<. Malformed Event Token.".format(token))
            return
            # raise ValueError("Malformed Event Token '{0}'".format(token))
        if token in self.unique_events:
            print("Skipping Event >>{0}<<. Unique Event Already Tracked.".format(token))
            return
        url = self.adjust_url("event")
        now = time.time()
        self.activity_state.event_count += 1
        self.activity_state.update_activity_state(now)

        created_at = self.get_utc_time(ts=now)
        time.sleep(random.randint(t1, t2))
        sent_at = self.get_utc_time()

        headers = self.headers_part()
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        data = self.data_part(created_at, sent_at)
        data["event_count"] = self.activity_state.event_count
        data["event_token"] = token
        if "installed_at" in data: del data["installed_at"]
        if "updated_at" in data: del data["updated_at"]
        data["subsession_count"] = self.activity_state.sub_session_count
        data["session_length"] = self.activity_state.session_length
        data["time_spent"] = self.activity_state.time_spent

        if "partner_params" in u_data and u_data["partner_params"] is None:
            del u_data["partner_params"]
        if "callback_params" in u_data and u_data["callback_params"] is None:
            del u_data["callback_params"]

        for deprecatedKeys in ["callback_params", "partner_params", "revenue", "currency"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)

        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(data.get('created_at'), ACTIVITY_EVENT)

        elif self.algo == "adj-new":
            data = collections.OrderedDict(data)
            auth = self.adj_new(data, ACTIVITY_EVENT, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        return self.network_request(request, save_attr)

    def adjust_s2s_event(self, u_headers={}, u_data={}, u_params={}, token=None, save_attr=True, event_meaning=None,
                         **kwargs):
        if not self.enable_tracking:
            print("{S2S EVENT} Tracking Disabled")
            return {}

        url = "https://s2s.adjust.com/event"
        headers = {
            "Accept-Encoding": "gzip",
            "User-Agent": "okhttp/4.9.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": self.s2s_auth
        }
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        if "s2s_adid" not in self.app:
            self.app["s2s_adid"] = self.google_adid or util.get_random_string("hex", 32)
        data = {
            "adid": self.from_app("s2s_adid"),
            "app_token": self.app_token,
            "created_at_unix": int(time.time()),
            "environment": self.environment,
            "event_token": token,
            "gps_adid": self.from_device('adid'),
            "s2s": "1"
        }

        for deprecatedKeys in ["callback_params", "partner_params", "revenue", "currency"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)
        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        return self.network_request(request, save_attr)

    def adjust_s2s_gtm_event(self, u_headers={}, u_data={}, u_params={}, token=None, save_attr=True,
                             event_meaning=None, **kwargs):
        if not self.enable_tracking:
            print("{S2S GTM EVENT} Tracking Disabled")
            return {}

        url = "https://s2s.adjust.com/gtm_event"
        headers = {
            "Accept-Encoding": "gzip",
            "User-Agent": "GoogleTagManager/5.06 (Linux; U; Android {0}; {1}-{2}; {3} Build/{4})".format(
                self.from_device("os_version"), self.device_language(), self.device_country().lower(),
                self.from_device("model"), self.from_device("build")
            ),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        data = {
            "app_token": self.app_token,
            "created_at_unix": int(time.time() * 1000),
            "environment": self.environment,
            "event_token": token,
            "gps_adid": self.from_device('adid'),
            "s2s": "1"
        }

        for deprecatedKeys in ["callback_params", "partner_params", "revenue", "currency"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)
        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        return self.network_request(request, save_attr)

    def adjust_sdk_click(self, u_headers={}, u_data={}, u_params={}, source=None, t1=0, t2=0, t3=0, t4=0,
                         save_attr=True, override_time=True, force_adj=False, **kwargs):
        if not self.enable_tracking:
            print("{SDK_CLICK} Tracking Disabled")
            return {}

        url = self.adjust_url("sdk_click")
        sdk_clk_time = ""
        if source in ["reftag", "deeplink"]:
            sdk_clk_time = self.get_utc_time()
            time.sleep(random.randint(t3, t4))

        if source == "install_referrer" and override_time and self.session_time:
            now = self.session_time + random.uniform(0.01, 0.05)
        else:
            now = time.time()
            time.sleep(random.randint(t1, t2))
        self.activity_state.update_activity_state(now)
        created_at = self.get_utc_time(ts=now)
        sent_at = self.get_utc_time()

        headers = self.headers_part()
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        data = self.data_part(created_at, sent_at)
        data["subsession_count"] = self.activity_state.sub_session_count
        data["session_length"] = self.activity_state.session_length
        data["time_spent"] = self.activity_state.time_spent

        if sdk_clk_time and self.day == 0:
            data["click_time"] = sdk_clk_time
        if source:
            data["source"] = source
            if source == 'install_referrer':
                if self.day == 0:
                    data.update({
                        "click_time": self.clicked_at(),
                        "install_begin_time": self.download_begin_at(),
                    })
                rfr = self.from_app('referrer')
                # The no-referrer placeholder carries a literal %20, not a space:
                # the winning capture's raw body is
                #   referrer=utm_source%3D%28not%2520set%29%26utm_medium%3D%28not%2520set%29
                # The %25 shows the value held "%20" before form encoding.  A real
                # space would go out as "+", which the capture never contains.
                data["referrer"] = urllib.parse.unquote(rfr) if rfr else 'utm_source=(not%20set)&utm_medium=(not%20set)'

                if built_cmp(self.sdk, "android4.21.1") >= 0:
                    data["referrer_api"] = "google"

                    if built_cmp(self.sdk, "android4.23.0") >= 0:
                        data.update({
                            "install_version": self.from_campaign("app_version_name"),
                            "google_play_instant": "0"
                        })
                        if self.day == 0:
                            data.update({
                                "click_time_server": self.clicked_at_server(),
                                "install_begin_time_server": self.download_begin_at_server(),
                            })
            elif source == "reftag":
                rfr = self.from_app('referrer')
                if rfr:
                    reftag = urlparse.parse_qs(urllib.parse.unquote(rfr)).get('adjust_reftag')
                    if reftag:
                        data["reftag"] = reftag[0]
                data.update({
                    "referrer": urllib.parse.unquote(rfr) if rfr else 'utm_source=(not%20set)&utm_medium=(not%20set)',
                    "raw_referrer": rfr or 'utm_source=(not%20set)&utm_medium=(not%20set)',
                })
            elif source == "deeplink":
                for _ in [
                    "android_uuid", "time_spent", "subsession_count", "session_length", "session_count", "last_interval"
                ]:
                    if _ in data:
                        del data[_]

        for deprecatedKeys in ["callback_params", "partner_params"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)

        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(data.get('created_at'), ACTIVITY_CLICK, source=source)

        elif self.algo == "adj-new":
            data = collections.OrderedDict(data)
            auth = self.adj_new(data, ACTIVITY_CLICK, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        resp = self.network_request(request, save_attr)
        if not self.google_adid:
            try:
                self.google_adid = json.loads(resp.get('data')).get('adid')
            except:
                pass
        return resp

    def adjust_ad_revenue(self, u_headers={}, u_data={}, u_params={}, t1=0, t2=0, save_attr=True, force_adj=False, **kwargs):
        # Call Added from Version 4.21.0"
        if not self.enable_tracking:
            print("{AD_REVENUE} Tracking Disabled")
            return {}

        url = self.adjust_url("ad_revenue")
        now = time.time()
        self.activity_state.update_activity_state(now)
        created_at = self.get_utc_time(ts=now)
        time.sleep(random.randint(t1, t2))
        sent_at = self.get_utc_time()

        headers = self.headers_part()
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        data = self.data_part(created_at, sent_at)
        data["subsession_count"] = self.activity_state.sub_session_count
        data["session_length"] = self.activity_state.session_length
        data["time_spent"] = self.activity_state.time_spent

        for deprecatedKeys in ["callback_params", "partner_params"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)

        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(data.get('created_at'), AD_REVENUE)

        elif self.algo == "adj-new":
            data = collections.OrderedDict(data)
            auth = self.adj_new(data, AD_REVENUE, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        return self.network_request(request, save_attr)

    def adjust_third_party_sharing(self, u_headers={}, u_data={}, u_params={}, sharing="enable", t1=0, t2=0,
                                   save_attr=True, force_adj=False, **kwargs):
        if not self.enable_tracking:
            print("{THIRT_PARTY_SHARING} Tracking Disabled")
            return {}

        url = self.adjust_url("third_party_sharing")

        headers = self.headers_part()
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        created_at = self.get_utc_time()
        time.sleep(random.randint(t1, t2))
        sent_at = self.get_utc_time()

        data = {
            "android_uuid": self.android_uuid(),
            "api_level": self.from_device("sdk"),
            "app_token": self.app_token,
            "app_version": self.from_campaign('app_version_name'),
            "attribution_deeplink": self.attribution_deeplink,
            "created_at": created_at,
            "device_name": self.from_device('model'),
            "device_type": self.device_type(),
            "environment": self.environment,
            "event_buffering_enabled": self.event_buffering_enabled,
            "gps_adid": self.from_device('adid'),
            "gps_adid_attempt": "1",
            "gps_adid_src": "service",
            "needs_response_details": self.needs_response_details,
            "os_name": "android",
            "os_version": self.from_device('os_version'),
            "package_name": self.from_campaign('package_name'),
            "sent_at": sent_at,
            "sharing": sharing,
            "tracking_enabled": "1",
        }
        for key in [AppData.FB_ID, AppData.PUSH_TOKEN, AppData.APP_SET_ID]:
            if key in self.app:
                data[key] = self.from_app(key)
        if built_cmp(self.sdk, "android4.28.4") >= 0:
            data["ui_mode"] = "1"

        for deprecatedKeys in ["callback_params", "partner_params"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)

        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(data.get('created_at'), THIRD_PARTY_SHARING)
        elif self.algo == "adj-new":
            data = collections.OrderedDict(data)
            auth = self.adj_new(data, THIRD_PARTY_SHARING, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        return self.network_request(request, save_attr)

    def adjust_attribution(self, u_headers={}, u_data={}, u_params={}, init_by="sdk", t1=0, t2=0, save_attr=True,
                           auth_params=False, fetch_response=False, force_adj=False, **kwargs):
        if not self.enable_tracking:
            print("{ATTRIBUTION} Tracking Disabled")
            return {}

        url = self.adjust_url("attribution")

        now = time.time()
        self.activity_state.update_activity_state(now)
        created_at = self.get_utc_time(ts=now)
        time.sleep(random.randint(t1, t2))
        sent_at = self.get_utc_time()

        headers = self.headers_part(content_type="")
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        # 4.12.0, 4.12.1, 4.12.2, 4.12.3, 4.12.4
        params = {
            "app_token": self.app_token,
            "attribution_deeplink": self.attribution_deeplink,
            "created_at": created_at,
            "environment": self.environment,
            "foreground": "1",
            "gps_adid": self.from_device('adid'),
            "needs_response_details": self.needs_response_details,
            "offline_mode_enabled": "0",
            "sent_at": sent_at,
            "tracking_enabled": "1"
        }
        if AppData.PUSH_TOKEN in self.app:
            params["push_token"] = self.from_app(AppData.PUSH_TOKEN)
        if self.device_known is not None:
            params["device_known"] = self.device_known
        if self.needs_cost is not None:
            params["needs_cost"] = self.needs_cost
        if self.sdk not in ["android4.12.0", "android4.12.1", "android4.12.2", "android4.12.3", "android4.12.4"]:
            params["initiated_by"] = init_by

        if built_cmp(self.sdk, "android4.16.0") >= 0:
            params.update({
                "android_uuid": self.android_uuid(),
                "api_level": self.from_device("sdk"),
                "app_version": self.from_campaign('app_version_name'),
                "device_name": self.from_device('model'),
                "device_type": self.device_type(),
                "gps_adid_src": "service",
                "os_name": "android",
                "os_version": self.from_device('os_version'),
                "package_name": self.from_campaign('package_name'),
            })
            if built_cmp(self.sdk, "android4.21.0") >= 0:
                if self.sdk not in ["android4.21.0", "android4.21.1"]:
                    params["gps_adid_attempt"] = "1"

                if built_cmp(self.sdk, "android4.28.3") < 0:
                    if self.algo == "sha256":
                        params["app_secret"] = self.secret_key
                        params["secret_id"] = self.secret_id

                if built_cmp(self.sdk, "android4.28.4") >= 0:
                    params["ui_mode"] = "1"
        for key in [AppData.APP_SET_ID]:
            if key in self.app:
                params[key] = self.from_app(key)

        for deprecatedKeys in ["callback_params", "partner_params"]:
            if u_params.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_params[deprecatedKeys] = val
        if u_params and isinstance(u_params, dict):
            params.update(u_params)
        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(params.get('created_at'), ACTIVITY_ATTRIBUTION)
        elif self.algo == "adj-new":
            params = collections.OrderedDict(params)
            auth = self.adj_new(params, ACTIVITY_ATTRIBUTION, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        if fetch_response:
            req_method = METHOD_GET
        else:
            req_method = METHOD_HEAD
        request = {'url': url, 'httpmethod': req_method, 'headers': headers, 'params': params, 'data': u_data}
        return self.network_request(request, save_attr)

    def adjust_sdk_info(self, u_headers={}, u_data={}, u_params={}, source="push", t1=0, t2=0, save_attr=True, force_adj=False, **kwargs):
        if not self.enable_tracking:
            print("{SDK_INFO} Tracking Disabled")
            return {}

        url = self.adjust_url("sdk_info")

        now = time.time()
        self.activity_state.update_activity_state(now)
        created_at = self.get_utc_time(ts=now)
        time.sleep(random.randint(t1, t2))
        sent_at = self.get_utc_time()

        headers = self.headers_part()
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        data = {
            "app_token": self.app_token,
            "attribution_deeplink": self.attribution_deeplink,
            "created_at": created_at,
            "environment": self.environment,
            "event_buffering_enabled": self.event_buffering_enabled,
            "needs_response_details": self.needs_response_details,
            "sent_at": sent_at,
            "source": source
        }
        if self.device_known is not None:
            data["device_known"] = self.device_known
        if self.needs_cost is not None:
            data["needs_cost"] = self.needs_cost
        if source == "push":
            data["push_token"] = self.from_app(AppData.PUSH_TOKEN)

        if self.sdk in [
            "android4.12.0", "android4.12.1", "android4.12.2", "android4.12.3", "android4.12.4", "android4.13.0",
            "android4.14.0"
        ]:
            data["android_id"] = self.from_device('android_id')
        # Need to added after 4.13.0 and before 4.15.0
        if built_cmp(self.sdk, "android4.15.0") >= 0:
            data["tracking_enabled"] = "1"
            data["gps_adid"] = self.from_device('adid')

            if built_cmp(self.sdk, "android4.16.0") >= 0:
                data["gps_adid_src"] = "service"
                data["android_uuid"] = self.android_uuid()

                if built_cmp(self.sdk, "android4.21.2") >= 0:
                    data["gps_adid_attempt"] = "1"

        for deprecatedKeys in ["callback_params", "partner_params"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)

        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(data.get('created_at'), ACTIVITY_INFO, source)

        elif self.algo == "adj-new":
            auth = self.adj_new(data, ACTIVITY_INFO, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        return self.network_request(request, save_attr)

    # This call is not expected before Version 4.26.0; Also this call will come before session
    def adjust_measurement_constant(self, u_headers={}, u_data={}, u_params={}, measurement="enable", t1=0, t2=0,
                                    save_attr=True, force_adj=False, **kwargs):
        if not self.enable_tracking:
            print("{MEASUREMENT} Tracking Disabled")
            return {}

        url = self.adjust_url("measurement_consent")

        created_at = self.get_utc_time()
        time.sleep(random.randint(t1, t2))
        sent_at = self.get_utc_time()

        headers = self.headers_part()
        if u_headers and isinstance(u_headers, dict):
            headers.update(u_headers)

        data = {
            "android_uuid": self.android_uuid(),
            "api_level": self.from_device("sdk"),
            "app_token": self.app_token,
            "app_version": self.from_campaign('app_version_name'),
            "attribution_deeplink": self.attribution_deeplink,
            "created_at": created_at,
            "device_name": self.from_device('model'),
            "device_type": self.device_type(),
            "environment": self.environment,
            "event_buffering_enabled": self.event_buffering_enabled,
            "gps_adid": self.from_device('adid'),
            "gps_adid_attempt": "1",
            "gps_adid_src": "service",
            "needs_response_details": self.needs_response_details,
            "os_name": "android",
            "os_version": self.from_device('os_version'),
            "package_name": self.from_campaign('package_name'),
            "sent_at": sent_at,
            "tracking_enabled": "1"
        }
        if measurement:
            data["measurement"] = measurement
        if built_cmp(self.sdk, "android4.28.4") >= 0:
            data["ui_mode"] = "1"

        for deprecatedKeys in ["callback_params", "partner_params"]:
            if u_data.get(deprecatedKeys):
                print("Sending {0} in u_data is deprecated. Use {0} parameter instead.".format(deprecatedKeys))
            val = kwargs.get(deprecatedKeys)
            if val is not None:
                if isinstance(val, dict):
                    val = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
                u_data[deprecatedKeys] = val
        if u_data and isinstance(u_data, dict):
            data.update(u_data)
        if self.algo == "sha256":
            headers["Authorization"] = self.get_auth(data.get('created_at'), MEASUREMENT_CONSENT)

        elif self.algo == "adj-new":
            auth = self.adj_new(data, MEASUREMENT_CONSENT, force_adj=force_adj)
            if auth and auth.get("auth"):
                headers["Authorization"] = auth.get("auth")

        request = {'url': url, 'httpmethod': METHOD_POST, 'headers': headers, 'params': u_params, 'data': data}
        return self.network_request(request, save_attr)

    ######################################################################################################
    # Request and Response related Methods

    def network_request(self, request, save_attr):
        if self.algo and "headers" in request and "Authorization" in request["headers"] and request["headers"]["Authorization"] in [None, ""]:
            del request["headers"]["Authorization"]
        response = util.execute_request(**request)
        code = response.get('code')
        if save_attr:
            # Anything outside 2xx is a rejected call -- keep it, do not retry
            # it away.  A 4xx body is still the server's answer and is the
            # clearest signal we get that a request was not accepted.
            if code is not None and code not in (200, 201, 204):
                self.save_attribution_call_status(request, response)
            elif request['url'] == "https://{0}/session".format(self.adjust_domain):
                self.session_check = True

        if self.api_serv_data:
            # The original apiserv uploader is not in this tree; record the
            # call in-process instead so a debugger can still read it back.
            self.api_serv_data["payload"] = {
                'url': request.get("url"), 'method': request.get("httpmethod"),
                'headers': request.get("headers"),
                'params': request.get("params"), 'data': request.get("data"),
                'code': code,
            }
        return response

    def save_attribution_call_status(self, request, response):
        """Record a non-2xx answer and hand the response straight back.

        The original queued these to a RabbitMQ error mailbox, which is not
        reachable from here.  Keeping them in `self.call_failures` is enough
        to see what the server objected to.
        """
        entry = {
            'url': request.get('url'),
            'method': request.get('httpmethod'),
            'code': response.get('code'),
            'data': (response.get('data') or '')[:500],
        }
        if not hasattr(self, 'call_failures'):
            self.call_failures = []
        self.call_failures.append(entry)
        print("  [%s] %s -> %s  %s"
              % (entry['code'], entry['method'], entry['url'].rsplit('/', 1)[-1],
                 entry['data'][:120]))
        return response


