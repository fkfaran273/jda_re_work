import Java from 'frida-java-bridge';
'use strict';

var CAPTURED = {
  canonical: null,     // the exact string that gets HMAC'd
  lastHeader: null,    // the header u2 built
  lastBlobLen: 0,      // nSign() output size (expect 176)
  errors: []
};

// On spawn the agent loads before ART is up, so `Java` is not defined yet.
// Retry Java.perform() itself (it throws while the bridge is absent).
function install() {
  var done = false;
  try {
    Java.perform(function () {
      console.log('[adj9] inside Java.perform');
      var String = Java.use('java.lang.String');
    var HashMap = Java.use('java.util.HashMap');
    var Base64 = Java.use('android.util.Base64');

    // ------------------------------------------------------------ capture
    // d3.a(String) -> UTF-8 bytes; this is the canonical string right before HMAC
    try {
      var d3 = Java.use('com.adjust.sdk.sig.d3');
      d3.a.overload('java.lang.String').implementation = function (s) {
        var str = Java.cast(s, String).toString();
        CAPTURED.canonical = str;
        send({ type: 'canonical', value: str });
        return this.a(s);
      };
    } catch (e) { CAPTURED.errors.push('hook d3.a: ' + e); }

    // u2.a(LinkedHashMap, byte[]) -> the finished header string
    try {
      var u2 = Java.use('com.adjust.sdk.sig.u2');
      u2.a.overload('java.util.LinkedHashMap', '[B').implementation = function (map, blob) {
        var r = this.a(map, blob);
        CAPTURED.lastHeader = r;
        CAPTURED.lastBlobLen = blob.length;
        send({ type: 'header', value: r, blobLen: blob.length });
        return r;
      };
    } catch (e) { CAPTURED.errors.push('hook u2.a: ' + e); }

    // NativeLibHelper.a(Context, LinkedHashMap, byte[], int) -> nSign() output
    try {
      var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
      NLH.a.overload('android.content.Context', 'java.util.LinkedHashMap', '[B', 'int')
        .implementation = function (ctx, map, hmac, sdk) {
          var r = this.a(ctx, map, hmac, sdk);
          if (r !== null) {
            send({ type: 'nSign', outLen: r.length,
                   b64: Base64.encodeToString(r, 2) });
          }
          return r;
        };
    } catch (e) { CAPTURED.errors.push('hook NativeLibHelper.a: ' + e); }

    // ------------------------------------------------------------ rpc
    rpc.exports = {
      /**
       * Mint a signature.
       * @param obj.activity  {k: v}  activity params (order matters — see note)
       * @param obj.globals   {k: v}  MUST contain activity_kind and client_sdk
       * @returns {ok, authorization, canonical, blobLen} or {ok:false, error}
       */
      mint: function (obj) {
        var out = { ok: false, error: null };
        try {
          var Signer = Java.use('com.adjust.sdk.sig.Signer');
          var signer = Signer.$new();
          try { signer.onResume(); } catch (e) { /* not fatal */ }

          var act = HashMap.$new();
          Object.keys(obj.activity).forEach(function (k) {
            act.put(k, String.valueOf(obj.activity[k]));
          });
          var glob = HashMap.$new();
          Object.keys(obj.globals).forEach(function (k) {
            glob.put(k, String.valueOf(obj.globals[k]));
          });
          var res = HashMap.$new();

          var ctx = Java.use('android.app.ActivityThread')
                      .currentApplication().getApplicationContext();

          CAPTURED.canonical = null;
          CAPTURED.lastHeader = null;

          signer.sign.overload(
            'android.content.Context', 'java.util.Map',
            'java.util.Map', 'java.util.Map'
          ).call(signer, ctx, act, glob, res);

          var auth = res.get('authorization');
          out.ok = auth !== null && auth !== undefined;
          out.authorization = out.ok ? Java.cast(auth, String).toString() : null;
          out.canonical = CAPTURED.canonical;
          out.blobLen = CAPTURED.lastBlobLen;
          out.outMapKeys = [];
          var it = res.keySet().iterator();
          while (it.hasNext()) { out.outMapKeys.push(Java.cast(it.next(), String).toString()); }
        } catch (e) {
          out.error = (e && e.message) ? e.message : String(e);
          out.stack = (e && e.stack) ? e.stack : null;
        }
        return out;
      },

      /** Just read whatever the app itself last produced (no minting). */
      lastcapture: function () { return CAPTURED; },

      /** Sanity: is the native lib loaded and not locked down? */
      health: function () {
        try {
          var Signer = Java.use('com.adjust.sdk.sig.Signer');
          return { loaded: true, hasOnResume: (typeof Signer.onResume === 'function') };
        } catch (e) { return { loaded: false, error: String(e) }; }
      }
    };

    send({ type: 'ready', errors: CAPTURED.errors });
    console.log('[adj9] ready');
    });
    done = true;
  } catch (e) {
    console.log('[adj9] Java not ready yet (' + e + '), retry');
  }
  if (!done) setTimeout(install, 150);
}

setTimeout(install, 150);
