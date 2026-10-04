import Java from 'frida-java-bridge';

/* mintsame_src.js - THE determinism experiment, run inside the app process.
 *
 * Idea: hook com.adjust.sdk.sig.NativeLibHelper.a(Context, LinkedHashMap, byte[], int)
 * - the JNI entry that produces the 192-byte blob - and, after the app's own call,
 * call it AGAIN with byte-identical arguments. Under the proven header law the blob's
 * first 16 bytes are Random3(signing_second), so two results sharing a header were
 * signed in the SAME second:
 *
 *     same header + identical body    => the pipeline is deterministic given
 *                                        (map, H, second) => an offline signer is possible
 *     same header + different body    => per-call randomness => offline replica impossible
 *
 * Nothing is forged: every blob comes from the app's own native signer and keystore key.
 */
'use strict';

var OUT = { tries: 0, pairs: [], headers: {}, errors: [], ready: false };

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

function install() {
  try {
    Java.perform(function () {
      var B64 = Java.use('android.util.Base64');
      var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
      var hooked = false;
      try {
        NLH.a.overload('android.content.Context', 'java.util.LinkedHashMap', '[B', 'int')
          .implementation = function (ctx, map, hmac, sdk) {
            var r = this.a(ctx, map, hmac, sdk);
            try {
              if (!OUT.ready) {
                OUT.ready = true;
                send({ type: 'mintsame_ready', note: 'NLH hooked; hmacLen=' + (hmac ? hmac.length : -1) });
              }
              var N = 12;
              for (var i = 0; i < N; i++) {
                if (OUT.pairs.length >= 3) break;
                var b = null;
                try { b = this.a(ctx, map, hmac, sdk); } catch (e1) { OUT.errors.push('' + e1); break; }
                if (!b || b.length !== 192) { OUT.errors.push('len ' + (b ? b.length : -1)); break; }
                OUT.tries++;
                var hdr = hex(b);
                if (OUT.headers[hdr] === undefined) {
                  OUT.headers[hdr] = B64.encodeToString(b, 2);
                  continue;
                }
                var prev = null;
                try { prev = B64.decode(OUT.headers[hdr], 2); } catch (eD) { }
                var same = eq(prev, b);
                var rec = { header: hdr.slice(0, 32), same: same, n: OUT.tries,
                            a: OUT.headers[hdr], b: B64.encodeToString(b, 2) };
                OUT.pairs.push(rec);
                send({ type: 'same_second', result: rec });
              }
              send({ type: 'mintsame_done', pairs: OUT.pairs.length, tries: OUT.tries,
                     errors: OUT.errors.slice(0, 3) });
            } catch (e) { OUT.errors.push('loop: ' + e); }
            return r;
          };
        hooked = true;
      } catch (e) { OUT.errors.push('NLH hook: ' + e); }
      send({ type: 'mintsame_ready', hooked: hooked, errors: OUT.errors });
    });
  } catch (e) {
    send({ type: 'mintsame_ready', hooked: false, errors: ['Java not ready: ' + e] });
  }
}

install();