/* diffmap3_src.js - PROPER different-map pair: clone the golden 47 pairs for
 * mint A; for mint B change gps_adid to a FRESH uuid (the claim the server
 * joins on) while keeping everything else identical. Same H bytes, same
 * wall second (E2-aligned), same process. Verdict:
 *   regions identical => region ignores map content (f(second)-only)
 *   regions differ    => region takes map content (f(map,second))
 * NLH.a direct path (proven); persist mint_dg1/2.json.
 */
'use strict';

import Java from 'frida-java-bridge';

var PAIRS = null;

rpc.exports = {
  setpairs: function (p) { PAIRS = p; return { ok: true, n: p.length }; },
  doublet: function (gaidB) {
    var out = { ok: false, error: null };
    try {
      var r = Java.perform(function () {
        var LH = Java.use('java.util.LinkedHashMap');
        var Str = Java.use('java.lang.String');
        var B64 = Java.use('android.util.Base64');
        var FOS = Java.use('java.io.FileOutputStream');
        var H = Java.array('byte', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
        function mk(pairs) {
          var m = LH.$new();
          pairs.forEach(function (kv) {
            m.put(Str.$new(kv[0]), kv[1] === null ? null : Str.$new(kv[1]));
          });
          return m;
        }
        function dump(nm, o) {
          var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          var fp = ctx.getExternalFilesDir(null).getAbsolutePath() + '/' + nm;
          var fos = FOS.$new(fp);
          fos.write(Str.$new(JSON.stringify(o)).getBytes('UTF-8'));
          fos.close();
        }
        var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var nlh;
        try { nlh = NLH.$new(); }
        catch (eN) {
          var fN = null;
          Java.choose('com.adjust.sdk.sig.NativeLibHelper',
                      { onMatch: function (i) { fN = i; }, onComplete: function () { } });
          nlh = fN;
        }
        var spinStart = Date.now();
        while (Date.now() % 1000 > 80) { }
        var res = [];
        for (var mi = 0; mi < 2; mi++) {
          var prs = PAIRS.map(function (kv) { return [kv[0], kv[1]]; });
          if (mi === 1) {
            for (var j = 0; j < prs.length; j++) {
              if (prs[j][0] === 'gps_adid') prs[j][1] = gaidB;
            }
          }
          var blob = nlh.a(ctx, mk(prs), H, 31);
          var o = { ok: blob !== null && blob !== undefined && blob.length === 192,
                    gaid: mi === 0 ? prs.filter(function (kv) { return kv[0] === 'gps_adid'; })[0][1] : gaidB,
                    blobB64: blob ? B64.encodeToString(blob, 2) : null,
                    mapPairs: prs };
          res.push(o);
          dump('mint_dg' + (mi + 1) + '.json', o);
        }
        return { spun: Date.now() - spinStart, res: res };
      });
      out.ok = true;
      out.detail = r;
    } catch (e) { out.error = '' + e; }
    return out;
  }
};
