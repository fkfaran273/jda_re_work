// key2_hook.js — capture (msg, H) pairs from t1.a and key-gen/reset events from t1.b/a.
Java.perform(function () {
    var T1 = Java.use("com.adjust.sdk.sig.t1");
    var B64 = Java.use("android.util.Base64");

    function b64b(bytes) {
        if (bytes === null) return "null";
        return B64.encodeToString(bytes, 2 /*NO_WRAP*/);
    }

    // signing: a(Context, byte[]) -> byte[]  (HMAC over msg)
    T1.a.overload('android.content.Context', '[B')
        .implementation = function (ctx, msg) {
            var h = this.a(ctx, msg);
            send({ t: "sign", msg: b64b(msg), H: b64b(h) });
            return h;
        };

    // reset: a(Context) -> void   (deletes key2 + encrypted_key)
    T1.a.overload('android.content.Context')
        .implementation = function (ctx) {
            send({ t: "reset" });
            return this.a(ctx);
        };

    // init: b(Context) -> void   (generates key2)
    T1.b.overload('android.content.Context')
        .implementation = function (ctx) {
            var had = false;
            try {
                var KS = Java.use("java.security.KeyStore");
                var ks = KS.getInstance("AndroidKeyStore");
                ks.load(null);
                had = ks.containsAlias("key2");
            } catch (e) { }
            var r = this.b(ctx);
            send({ t: "keygen", existed_before: had });
            return r;
        };
    send({ t: "ready" });
});