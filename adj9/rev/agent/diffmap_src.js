/* diffmap_src.js - same-second DIFFERENT-map decisive pair, in-process.
 * On the first real Signer.sign hook, mint TWICE back-to-back (E2-aligned to
 * the same wall second):
 *   mint A: the app's own (act, glob) maps verbatim (putAll clone)
 *   mint B: the same maps but with ONE extra harmless claim? No - different
 *           activity_kind ('session' vs 'attribution') so the canonical map
 *           differs for sure, while H/second/process are identical.
 * Persist both blobs + maps to mint_diff1/2.json. The offline verdict:
 *   same second + different map -> same region  => region = f(second) ONLY
 *   same second + different map -> different region => region = f(map,second)
 * Pure-Java + the proven NLH.a path; no native hooks needed.
 */
'use strict';

var done = false;

import Java from 'frida-java-bridge';
Java.perform(function () {
  try {
    var Signer = Java.use('com.adjust.sdk.sig.Signer');
    Signer.sign.overload('android.content.Context', 'java.util.Map',
      'java.util.Map', 'java.util.Map').implementation = function (ctx, act, glob, res) {
      var base = this.sign(ctx, act, glob, res);
      if (!done) {
        done = true;
        try {
          var LHm = Java.use('java.util.LinkedHashMap');
          var StC = Java.use('java.lang.String');
          var B64 = Java.use('android.util.Base64');
          var FOS = Java.use('java.io.FileOutputStream');
          function clone(m) { var c = LHm.$new(); c.putAll(m); return c; }
          function pairs(m) {
            var arr = [], it = m.keySet().iterator();
            while (it.hasNext()) {
              var k = '' + it.next(), v = m.get(k);
              arr.push([k, (v === null || v === undefined) ? null : '' + v]);
            }
            return arr;
          }
          function dump(nm, obj) {
            try {
              var fp = ctx.getExternalFilesDir(null).getAbsolutePath() + '/' + nm;
              var fos = FOS.$new(fp);
              fos.write(StC.$new(JSON.stringify(obj)).getBytes('UTF-8'));
              fos.close();
            } catch (eF) { }
          }
          var spinStart = Date.now();
          while (Date.now() % 1000 > 80) { }
          send({ type: 'diffmap', status: 'aligned', spun: Date.now() - spinStart });
          var outs = [];
          var kinds = ['session', 'attribution'];
          for (var mi = 0; mi < 2; mi++) {
            var a2 = clone(act), g2 = clone(glob);
            a2.put(StC.$new('activity_kind'), StC.$new(kinds[mi]));
            g2.put(StC.$new('activity_kind'), StC.$new(kinds[mi]));
            var r2 = LHm.$new();
            var pb = null, errN = null;
            try { pb = this.sign(ctx, a2, g2, r2); } catch (eS) { errN = '' + eS; }
            var auth = null;
            try {
              var it2 = r2.keySet().iterator();
              while (it2.hasNext()) {
                var kk = '' + it2.next();
                if (kk === 'authorization') auth = '' + r2.get(kk);
              }
            } catch (eA) { }
            var o = { ok: pb !== null && pb !== undefined && pb.length === 192,
                      error: errN, kind: kinds[mi],
                      blobB64: pb ? B64.encodeToString(pb, 2) : null,
                      auth: auth,
                      mapPairs: pairs(a2).concat(pairs(g2)) };
            outs.push(o);
            dump('mint_diff' + (mi + 1) + '.json', o);
            send({ type: 'diffmap', status: 'mint', i: mi, ok: o.ok });
          }
          send({ type: 'diffmap', status: 'done' });
        } catch (e) { send({ type: 'diffmap', status: 'err', err: '' + e }); }
      }
      return base;
    };
    send({ type: 'diffmap', status: 'hooked' });
  } catch (e) { send({ type: 'diffmap', status: 'install-err', err: '' + e }); }
});
