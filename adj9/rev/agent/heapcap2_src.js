/* heapcap2_src.js - log the RAW POINTERS (addresses) of ctx/map/hmac/values,
 * not identityHashCode (which is stable per object, not the address).
 * Low32 of those addresses == the #0 W/C candidates DIRECTLY.
 * Also log map.entrySet iteration ORDER addresses (node pointers).
 */
'use strict';

rpc.exports = {
  ping: function () { return { ok: true }; }
};

function lo32(p) { return p.toInt32() >>> 0; }

import Java from 'frida-java-bridge';
Java.perform(function () {
  try {
    var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
    var ov = null;
    NLH.a.overloads.forEach(function (o) {
      if (o.argumentTypes.length === 4) ov = o;
    });
    if (!ov) { send({ type: 'heapcap2', status: 'no-4arg' }); return; }
    var n = 0;
    ov.implementation = function (ctx, map, hmac, sdk) {
      var r = this.a(ctx, map, hmac, sdk);
      try {
        n++;
        var rec = { n: n, sdk: sdk, size: map.size() };
        rec.ctxPtr = lo32(ptr(ctx.$handle));
        rec.mapPtr = lo32(ptr(map.$handle));
        rec.hmacPtr = hmac ? lo32(ptr(hmac.$handle)) : 0;
        var ks = map.keySet().iterator();
        var vh = [];
        while (ks.hasNext()) {
          var k = ks.next();
          var v = map.get(k);
          vh.push(['' + k, v === null ? 0 : lo32(ptr(v.$handle))]);
        }
        rec.vals = vh;
        send({ type: 'heapcap2', status: 'sign', rec: rec,
               blobLen: r ? r.length : 0 });
      } catch (e) { send({ type: 'heapcap2', status: 'err', err: '' + e }); }
      return r;
    };
    send({ type: 'heapcap2', status: 'hooked' });
  } catch (e) { send({ type: 'heapcap2', status: 'install-err', err: '' + e }); }
});
