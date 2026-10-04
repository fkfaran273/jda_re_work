"""mk_secdrift.py - build secdrift_src.js from the proven appcap_src.js.

Changes (targeted string replacements, so the guard/plane code stays the exact
build that is known to work):
  * EMIT/LENQ entries gain a Date.now() ms timestamp (4th element) -> every
    region stream becomes attributable to a specific mint (the problem that
    made seg27 unattributable);
  * the Java blob hook also records MINTS = [{ts, header}] per 192-B blob;
  * auto-flush keeps REFRESHING the dump while the capture grows;
  * new rpc: armSign(count, gapms) - hooks Signer.sign, captures the map once,
    then re-signs the SAME map N times spaced gapms apart (different seconds);
  * dump payload carries mints + errs.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "appcap_src.js"), encoding="utf-8").read()
orig = src


def sub(a, b, note):
    global src
    assert a in src, "pattern not found: " + note
    src = src.replace(a, b)


# 1. timestamps on EMIT
sub("try { EMITS.push([a[1].toInt32() >>> 0, a[2].toInt32() >>> 0, a[3].toInt32() >>> 0]); } catch (e) { }",
    "try { EMITS.push([a[1].toInt32() >>> 0, a[2].toInt32() >>> 0, a[3].toInt32() >>> 0, Date.now()]); } catch (e) { }",
    "emit")

# 2. timestamps on LENQ
sub("try { LENQ.push([this.st, this.nn, r.toInt32() >>> 0]); } catch (e) { }",
    "try { LENQ.push([this.st, this.nn, r.toInt32() >>> 0, Date.now()]); } catch (e) { }",
    "lenq")

# 3. MINTS recording in the blob hook
sub("                  BLOBS.push(B64.encodeToString(r, 2));",
    "                  BLOBS.push(B64.encodeToString(r, 2));\n"
    "                  var _h = '';\n"
    "                  for (var _i = 0; _i < 16; _i++) _h += ('0' + (r[_i] & 0xff).toString(16)).slice(-2);\n"
    "                  MINTS.push({ ts: Date.now(), header: _h });",
    "blob")

# 4. state vars
sub("var dumped = false;",
    "var dumped = false, lastWrite = -1;\n"
    "var MINTS = [], ERR = [];\n"
    "var signHooked = false, planCount = 0, planGap = 1400, mintsDone = 0, saved = null;",
    "state")

# 5. auto-flush refreshes instead of latching
sub("          if (!dumped && EMITS.length > 300) {",
    "          if (EMITS.length > 300 && EMITS.length !== lastWrite) {",
    "autoflush")
sub("    res.bytes = n;\n    dumped = true;",
    "    res.bytes = n;\n    dumped = true;\n    lastWrite = EMITS.length;",
    "writeDump tail")

# 6. dump payload
sub("    var o = { nemit: EMITS.length, nlenq: LENQ.length, blobs: BLOBS,\n              emits: EMITS, lenq: LENQ };",
    "    var o = { nemit: EMITS.length, nlenq: LENQ.length, blobs: BLOBS,\n"
    "              mints: MINTS, errs: ERR.slice(0, 10), emits: EMITS, lenq: LENQ };",
    "dump payload")

print("phase1 ok")

# 7. armSign + delayed re-sign loop, inserted before rpc.exports
ARM = '''
/* ---- armSign: hook Signer.sign once, then re-sign the SAME map at N
 * different seconds (gapms apart). Fresh clones per mint; blobs are captured
 * by the Java blob hook with their own ms timestamps. ---- */
function mintOnce(k) {
  Java.perform(function () {
    try {
      var LH = Java.use('java.util.LinkedHashMap');
      var a1 = LH.$new(); a1.putAll(saved.a1);
      var a2 = LH.$new(); a2.putAll(saved.a2);
      var a3 = saved.a3 ? LH.$new() : null;
      if (a3) a3.putAll(saved.a3);
      send({ type: 'mint', k: k, t: Java.use('java.lang.System').currentTimeMillis() });
      saved.ov.apply(saved.inst, [saved.ctx, a1, a2, a3]);
      mintsDone++;
    } catch (e) { ERR.push('mint' + k + ': ' + e); send({ type: 'mint_err', k: k, e: '' + e }); }
  });
}

function scheduleMints() {
  for (var k = 0; k < planCount; k++) {
    (function (k) { setTimeout(function () { mintOnce(k); }, 200 + k * planGap); })(k);
  }
  send({ type: 'scheduled', n: planCount, gap: planGap });
}

function armSign() {
  if (signHooked) return 'already';
  Java.perform(function () {
    var Signer = Java.use('com.adjust.sdk.sig.Signer');
    var ovs = Signer.sign.overloads;
    for (var j = 0; j < ovs.length; j++) {
      (function (ov) {
        var sig = ov.argumentTypes.map(function (t) { return t.className; }).join(',');
        ov.implementation = function () {
          var args = arguments;
          try {
            if (!saved && args.length >= 3 && args[1] && args[2]) {
              var LH = Java.use('java.util.LinkedHashMap');
              var a1c = LH.$new(); a1c.putAll(args[1]);
              var a2c = LH.$new(); a2c.putAll(args[2]);
              var a3c = args[3] ? LH.$new() : null;
              if (a3c) a3c.putAll(args[3]);
              saved = { inst: this, ov: ov, sig: sig, ctx: args[0], a1: a1c, a2: a2c, a3: a3c };
              send({ type: 'saved', sig: sig });
              if (planCount > 0) scheduleMints();
            }
          } catch (e) { ERR.push('sign-hook: ' + e); }
          return ov.apply(this, args);
        };
      })(ovs[j]);
    }
    signHooked = true;
    send({ type: 'signhooked', n: ovs.length });
  });
  return 'ok';
}

'''
sub("rpc.exports = {", ARM + "rpc.exports = {", "rpc")

# 8. new rpc entry + richer status
sub("  forceSession: function () {",
    "  armSign: function (count, gapms) {\n"
    "    planCount = count || 5;\n"
    "    planGap = gapms || 1400;\n"
    "    var r = armSign();\n"
    "    return { ok: true, r: r, count: planCount, gap: planGap };\n"
    "  },\n"
    "  forceSession: function () {",
    "forceSession")
sub("    return { armed: armed, nemit: EMITS.length, nlenq: LENQ.length, nblob: BLOBS.length };",
    "    return { armed: armed, nemit: EMITS.length, nlenq: LENQ.length,\n"
    "             nblob: BLOBS.length, nmint: MINTS.length, saved: !!saved,\n"
    "             mintsDone: mintsDone, errs: ERR.slice(0, 5) };",
    "status")

out = os.path.join(HERE, "secdrift_src.js")
open(out, "w", encoding="utf-8").write(src)
print("wrote %s (%d bytes)" % (out, len(src)))
print("has armSign:", "armSign: function" in src)
print("has MINTS:", "MINTS.push" in src)
print("emit ts:", ", Date.now()]" in src)

