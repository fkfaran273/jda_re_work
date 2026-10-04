import Java from 'frida-java-bridge';

/* mintsame2_src.js - determinism experiment, overload-tolerant + Signer-level loop.
 *
 * Run 2 lessons: hooking one NLH overload fired nothing (and a non-matching
 * overload raises no error), and Signer.sign is the proven-firing path. So:
 *   * hook EVERY overload of NativeLibHelper.a and Signer.sign and log which fires;
 *   * on a Signer.sign hit, re-sign the SAME cloned maps N times via this.sign()
 *     (the path proven to produce blobs) and, for every blob captured from the
 *     NativeLibHelper hook, compare headers: two blobs with an equal header were
 *     produced in the same second, so their bodies decide determinism.
 */
'use strict';

var OUT = { calls: [], pairs: [], tries: 0, seen: {}, errors: [], last: null };

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

function record(b, B64, tag) {
  if (!b || b.length !== 192) return;
  var hdr = hex(b).slice(0, 32);
  if (OUT.seen[hdr] === undefined) {
    OUT.seen[hdr] = { b64: B64.encodeToString(b, 2), tag: tag };
    return;
  }
  var prev = null;
  try { prev = B64.decode(OUT.seen[hdr].b64, 2); } catch (e) { }
  var rec = { header: hdr, same: eq(prev, b), first: OUT.seen[hdr].b64,
              second: B64.encodeToString(b, 2) };
  OUT.pairs.push(rec);
  send({ type: 'same_second', result: rec });
}

Java.perform(function () {
  var B64 = Java.use('android.util.Base64');

  // ---- 1. every overload of NativeLibHelper.a, logging which one is called ----
  try {
    var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
    var ovs = NLH.a.overloads;
    for (var i = 0; i < ovs.length; i++) {
      (function (ov) {
        var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(',');
        ov.implementation = function () {
          var r = ov.apply(this, arguments);
          try {
            if (OUT.calls.indexOf('NLH.a(' + sig + ')') < 0) {
              OUT.calls.push('NLH.a(' + sig + ')');
              send({ type: 'call', sig: 'NLH.a', args: sig });
            }
            // the byte[] arg is the 192-byte blob in the 3-arg-with-bytes overload
            for (var k = 0; k < arguments.length; k++) {
              var a = arguments[k];
              if (a && a.length === 192) record(a, B64, 'NLH');
            }
          } catch (e) { OUT.errors.push('NLH rec: ' + e); }
          return r;
        };
      })(ovs[i]);
    }
    send({ type: 'hooks', nlh: ovs.length, errors: OUT.errors.slice(0, 3) });
  } catch (e) { OUT.errors.push('NLH: ' + e); send({ type: 'hooks', nlh: -1, err: '' + e }); }

  // ---- 2. every overload of Signer.sign: capture maps, log, and loop ----
  try {
    var Signer = Java.use('com.adjust.sdk.sig.Signer');
    var sovs = Signer.sign.overloads;
    for (var j = 0; j < sovs.length; j++) {
      (function (ov) {
        var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(',');
        ov.implementation = function () {
          var args = arguments;
          try {
            if (OUT.calls.indexOf('sign(' + sig + ')') < 0) {
              OUT.calls.push('sign(' + sig + ')');
              send({ type: 'call', sig: 'Signer.sign', args: sig });
            }
            // find (ctx, actMap, globMap, outMap) regardless of overload shape
            if (args.length >= 4 && args[1] && args[2] && args[3]) {
              var LH = Java.use('java.util.LinkedHashMap');
              var ctx = args[0];
              for (var t = 0; t < 6; t++) {
                if (OUT.pairs.length >= 3) break;
                var a2 = LH.$new(); a2.putAll(args[1]);
                var g2 = LH.$new(); g2.putAll(args[2]);
                var r2 = LH.$new();
                OUT.tries++;
                try { this.sign.apply(this, [ctx, a2, g2, r2]); }
                catch (eS) { OUT.errors.push('re-sign: ' + eS); break; }
              }
              send({ type: 'loopdone', tries: OUT.tries, pairs: OUT.pairs.length,
                     errors: OUT.errors.slice(0, 3) });
            }
          } catch (e) { OUT.errors.push('sign: ' + e); }
          return ov.apply(this, args);
        };
      })(sovs[j]);
    }
    send({ type: 'hooks', sign: sovs.length });
  } catch (e) { send({ type: 'hooks', sign: -1, err: '' + e }); }

  send({ type: 'mintsame_ready', calls: OUT.calls, errors: OUT.errors.slice(0, 3) });
});