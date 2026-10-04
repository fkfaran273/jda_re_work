/* heapcap_src.js - capture the JAVA objects whose identities may seed #0/#2/#4.
 * Inside the app process, on each NativeLibHelper.a(ctx, map, hmac, sdk) call,
 * record System.identityHashCode of: ctx, map, hmac(byte[]), each map VALUE
 * string, plus map.size(). Two back-to-back mints with the SAME args show
 * whether identities repeat (deterministic -> offline OK) or differ per call.
 * Pure-Java: no native hooks, no ptrace issues.
 */
'use strict';

rpc.exports = {
  ping: function () { return { ok: true }; }
};

import Java from 'frida-java-bridge';
Java.perform(function () {
  try {
    var Sys = Java.use('java.lang.System');
    var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
    var ov = null;
    NLH.a.overloads.forEach(function (o) {
      if (o.argumentTypes.length === 4) ov = o;
    });
    if (!ov) { send({ type: 'heapcap', status: 'no-4arg' }); return; }
    var n = 0;
    ov.implementation = function (ctx, map, hmac, sdk) {
      var r = this.a(ctx, map, hmac, sdk);
      try {
        n++;
        var ids = {};
        ids.ctx = Sys.identityHashCode(ctx);
        ids.map = Sys.identityHashCode(map);
        ids.hmac = hmac ? Sys.identityHashCode(hmac) : 0;
        ids.sdk = sdk;
        ids.size = map.size();
        var ks = map.keySet().iterator();
        var vh = [];
        while (ks.hasNext()) {
          var k = '' + ks.next();
          var v = map.get(k);
          vh.push([k, v === null ? 0 : Sys.identityHashCode(v)]);
        }
        ids.vals = vh;
        send({ type: 'heapcap', status: 'sign', n: n, ids: ids });
      } catch (e) { send({ type: 'heapcap', status: 'err', err: '' + e }); }
      return r;
    };
    send({ type: 'heapcap', status: 'hooked' });
  } catch (e) { send({ type: 'heapcap', status: 'install-err', err: '' + e }); }
});
