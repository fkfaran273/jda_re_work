import Java from 'frida-java-bridge';

/* repeat_src.js - rerun the app's OWN native sign, synchronously, inside ITS process.
 *
 * On the first NativeLibHelper.a(ctx, map, hmac, sdk) call after load, keep the
 * captured (ctx, map, hmac, sdk) and re-invoke this.a(...) N times with the same
 * object references. Compare the returned 192 B blobs:
 *   same header + identical body => same (map,H,second) => deterministic
 *   same header + different body => per-call randomness (pointers/secure-random)
 * outside the arguments => #0/#2/#4 must be re-derived per call
 * The app itself recovers nothing: results are written to a JSON file we pull.
 */
'use strict';

var TRIES = 6;

function hex(a) {
  var s = '';
  for (var i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
  return s;
}

function eq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

var done = false;

Java.perform(function () {
  var B64 = Java.use('android.util.Base64');
  var STR = Java.use('java.lang.String');
  var FOS = Java.use('java.io.FileOutputStream');
  try {
    var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
    var ov = null;
    NLH.a.overloads.forEach(function (o) {
      if (o.argumentTypes.length === 4) ov = o;
    });
    if (!ov) { send({ type: 'repeat', status: 'no-4arg-overload' }); return; }
    ov.implementation = function (ctx, map, hmac, sdk) {
      var base = this.a(ctx, map, hmac, sdk);
      if (!done) {
        done = true;
        try {
          var blobs = [B64.encodeToString(base, 2)];
          for (var i = 0; i < TRIES; i++) {
            var r = this.a(ctx, map, hmac, sdk);
            blobs.push(B64.encodeToString(r, 2));
          }
          var hdrs = {};
          var out = { blobs: blobs, pairs: [] };
          for (var j = 0; j < blobs.length; j++) {
            var h = blobs[j].slice(0, 24);
            if (hdrs[h] === undefined) { hdrs[h] = j; continue; }
            out.pairs.push({ i: hdrs[h], j: j,
                             same: blobs[hdrs[h]] === blobs[j] });
          }
          try {
            var fp = ctx.getExternalFilesDir(null).getAbsolutePath() + '/repeat_out.json';
            var fos = FOS.$new(fp);
            fos.write(STR.$new(JSON.stringify(out)).getBytes('UTF-8'));
            fos.close();
          } catch (eF) { }
          send({ type: 'repeat', status: 'done', blobs: blobs.length,
                 pairs: out.pairs });
        } catch (e) { send({ type: 'repeat', status: 'err', err: '' + e }); }
      }
      return base;
    };
    send({ type: 'repeat', status: 'hooked' });
  } catch (e) { send({ type: 'repeat', status: 'install-err', err: '' + e }); }
});