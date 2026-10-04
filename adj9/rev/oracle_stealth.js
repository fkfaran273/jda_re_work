  send({ type: 'ready', errors: errs });

  /* ---- mint RPC (top-level inside Java.perform closure) ---- */
  rpc.exports = {
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
          var capC = null, blobB64 = null;
          var d3 = Java.use('com.adjust.sdk.sig.d3');
          var oA = d3.a.overload('java.lang.String');
          d3.a.overload('java.lang.String').implementation = function (s) {
            capC = s; return oA.call(this, s);
          };
          var NV = Java.use('com.adjust.sdk.sig.NativeLibHelper');
          var oN = NV.a.overload('android.content.Context',
                                 'java.util.LinkedHashMap', '[B', 'int');
          NV.a.overload('android.content.Context',
                        'java.util.LinkedHashMap', '[B', 'int')
             .implementation = function (c2, m, h, sd) {
            var r = oN.call(this, c2, m, h, sd);
            if (r !== null) blobB64 = Java.use('android.util.Base64').encodeToString(r, 2);
            return r;
          };
          signer.sign.overload('android.content.Context', 'java.util.Map',
                               'java.util.Map', 'java.util.Map')
                     .call(signer, ctx, act, glob, res);
          d3.a.overload('java.lang.String').implementation = null;
          NV.a.overload('android.content.Context',
                        'java.util.LinkedHashMap', '[B', 'int').implementation = null;
          var auth = res.get('authorization');
          out.ok = (auth !== null && auth !== undefined);
          out.authorization = out.ok ? Java.cast(auth, String).toString() : null;
          out.canonical = capC;
          out.blobB64 = blobB64;
          if (!out.ok) out.error = 'no authorization in outMap';
        } catch (e) {
          out.error = (e && e.message) ? e.message : String(e);
        }
      });
      return out;
    }
  };
  console.log('[agent] mint RPC exported');