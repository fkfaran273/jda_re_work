// oracle_hook.js — minimal device-signing oracle, exports defined at top level.
'use strict';
function b64(bytes) {
    return Java.use('android.util.Base64').encodeToString(bytes, 2);
}

rpc.exports = {
    health: function () {
        var out = {};
        Java.perform(function () {
            try {
                var Signer = Java.use('com.adjust.sdk.sig.Signer');
                out.loaded = true;
            } catch (e) { out.loaded = false; out.error = String(e); }
        });
        return out;
    },
    mint: function (obj) {
        var out = { ok: false, error: null };
        Java.perform(function () {
            try {
                var HashMap = Java.use('java.util.HashMap');
                var Signer = Java.use('com.adjust.sdk.sig.Signer');
                var signer = Signer.$new();
                try { signer.onResume(); } catch (e) { }

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

                var capCanonical = null, capBlobLen = 0;
                var d3 = Java.use('com.adjust.sdk.sig.d3');
                var origA = d3.a.overload('java.lang.String');
                d3.a.overload('java.lang.String').implementation = function (s) {
                    capCanonical = s;
                    return origA.call(this, s);
                };
                var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
                var origN = NLH.a.overload('android.content.Context',
                                           'java.util.LinkedHashMap', '[B', 'int');
                var blobB64 = null;
                NLH.a.overload('android.content.Context',
                               'java.util.LinkedHashMap', '[B', 'int')
                   .implementation = function (ctx2, map, hmac, sdk) {
                    var r = origN.call(this, ctx2, map, hmac, sdk);
                    if (r !== null) blobB64 = b64(r);
                    return r;
                };

                signer.sign.overload('android.content.Context', 'java.util.Map',
                                     'java.util.Map', 'java.util.Map')
                           .call(signer, ctx, act, glob, res);

                d3.a.overload('java.lang.String').implementation = null;
                NLH.a.overload('android.content.Context',
                               'java.util.LinkedHashMap', '[B', 'int').implementation = null;

                var auth = res.get('authorization');
                out.ok = (auth !== null && auth !== undefined);
                out.authorization = out.ok ? Java.cast(auth, String).toString() : null;
                out.canonical = capCanonical;
                out.blobB64 = blobB64;
                if (!out.ok) out.error = 'no authorization in outMap';
            } catch (e) {
                out.error = (e && e.message) ? e.message : String(e);
            }
        });
        return out;
    }
};
send({ t: "ready" });