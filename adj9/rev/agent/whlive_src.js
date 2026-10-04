/* whlive_src.js - capture the descriptor/body plane the way fin_descs.json was
 * built: hook LENQ 0x147304 (onEnter x0=stream, x1=n ; onLeave = value) so every
 * word the VM READS is recorded, plus EMIT 0x146ed8 for the output plane.
 * Then call NLH.a(ctx, map, H, 31) and persist everything to wh_out.json on the
 * device (large RPC payloads get dropped silently).
 */
'use strict';

import Java from 'frida-java-bridge';

var PAIRS = null;
var LENQ = [];
var EMITS = [];
var armed = false;
var hooked = false;
var CALL_TID = -1;
var CAP = 300000;

Process.setExceptionHandler(function (details) {
  var astr = details.address ? details.address.toString() : '0x0';
  var a = parseInt(astr, 16);
  var poisoned = astr.indexOf('0x600') === 0 && !isNaN(a) &&
                 a >= 0x600000000000 && a <= 0x700000000000;
  if (!poisoned) return false;
  try { details.context.pc = details.context.lr; } catch (e) { }
  return true;
});
try {
  function findExp(mod, name) {
    try { return Module.getGlobalExportByName(name); } catch (e) { }
    try { return Process.getModuleByName(mod).findExportByName(name); } catch (e) { }
    try { return Module.findExportByName(mod, name); } catch (e) { }
    return null;
  }
  var pthreadExit = findExp('libc.so', 'pthread_exit');
  var exitPtr = findExp('libc.so', 'exit');
  var killPtr = findExp('libc.so', 'kill');
  var tgkillPtr = findExp('libc.so', 'tgkill');
  function die(code, who) {
    send({ type: 'block', note: who + '(' + code + ')' });
    if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
  }
  if (exitPtr) Interceptor.replace(exitPtr, new NativeCallback(function (c) { die(c, 'exit'); }, 'void', ['int']));
  if (killPtr) {
    var oK = new NativeFunction(killPtr, 'int', ['int', 'int']);
    Interceptor.replace(killPtr, new NativeCallback(function (p, s) {
      if (p === Process.id) { send({ type: 'block', note: 'kill(self)' }); return 0; }
      return oK(p, s);
    }, 'int', ['int', 'int']));
  }
  if (tgkillPtr) {
    var oT = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
    Interceptor.replace(tgkillPtr, new NativeCallback(function (g, t, s) {
      if (g === Process.id && (s === 9 || s === 6)) { send({ type: 'block', note: 'tgkill(self)' }); return 0; }
      return oT(g, t, s);
    }, 'int', ['int', 'int', 'int']));
  }
  send({ type: 'log', note: 'guards disarmed' });
} catch (e) { send({ type: 'log', note: 'guard err: ' + e }); }

function libBase() {
  var ms = Process.enumerateModules();
  for (var i = 0; i < ms.length; i++) if (ms[i].path.indexOf('libsigner.so') >= 0) return ms[i].base;
  return null;
}

function hookAll() {
  if (hooked) return 'already';
  var b = libBase();
  if (!b) return 'no-libsigner';
  try {
    /* nSign entry: learn which thread performs the signing, so emit/lenq from
     * other threads (the app's own concurrent SDK work) can be filtered out --
     * without this the plane mixes several signings and roles get scrambled. */
    Interceptor.attach(b.add(0xdb1cc), {
      onEnter: function () { CALL_TID = this.threadId; }
    });
    Interceptor.attach(b.add(0x147304), {
      onEnter: function (a) {
        if (!armed || (CALL_TID >= 0 && this.threadId !== CALL_TID)) return;
        this.on = true;
        try { this.st = a[0].toString(); this.nn = a[1].toInt32() >>> 0; } catch (e) { this.on = false; }
      },
      onLeave: function (r) {
        if (!this.on || !armed || LENQ.length > CAP) return;
        try { LENQ.push([this.st, this.nn, r.toInt32() >>> 0]); } catch (e) { }
      }
    });
    Interceptor.attach(b.add(0x146ed8), {
      onEnter: function (a) {
        if (!armed || EMITS.length > CAP) return;
        if (CALL_TID >= 0 && this.threadId !== CALL_TID) return;
        try { EMITS.push([a[1].toInt32() >>> 0, a[2].toInt32() >>> 0, a[3].toInt32() >>> 0]); } catch (e) { }
      }
    });
    hooked = true;
    return b.toString();
  } catch (e) { return 'err:' + e; }
}
rpc.exports = {
  setpairs: function (p) { PAIRS = p; return { ok: true, n: p.length }; },
  harvest: function (gaidOverride) {
    var out = { ok: false, error: null };
    try {
      var r = Java.perform(function () {
        var LH = Java.use('java.util.LinkedHashMap');
        var Str = Java.use('java.lang.String');
        var B64 = Java.use('android.util.Base64');
        var FOS = Java.use('java.io.FileOutputStream');
        var H = Java.array('byte', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
        function dump(nm, o) {
          var dctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          var fp = dctx.getExternalFilesDir(null).getAbsolutePath() + '/' + nm;
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
        if (!nlh) return { fatal: 'no NativeLibHelper instance' };
        var hk = hookAll();
        var m = LH.$new();
        var used = [];
        PAIRS.forEach(function (kv) {
          var v = kv[1];
          if (kv[0] === 'gps_adid' && gaidOverride) v = gaidOverride;
          m.put(Str.$new(kv[0]), v === null ? null : Str.$new(v));
          used.push([kv[0], v]);
        });
        LENQ = []; EMITS = [];
        CALL_TID = Process.getCurrentThreadId();
        armed = true;
        var blob = nlh.a(ctx, m, H, 31);
        armed = false;
        var tidUsed = CALL_TID;
        CALL_TID = -1;
        var o = { blobB64: blob ? B64.encodeToString(blob, 2) : null,
                  nlenq: LENQ.length, nemit: EMITS.length,
                  tid: tidUsed,
                  hB64: B64.encodeToString(H, 2),
                  mapPairs: used,
                  lenq: LENQ, emits: EMITS };
        try { dump('wh_out.json', o); } catch (eD) { }
        return { blobB64: o.blobB64, nlenq: o.nlenq, nemit: o.nemit, hk: hk };
      });
      out.ok = true;
      out.detail = r;
    } catch (e) { out.error = '' + e; }
    return out;
  }
};

send({ type: 'whlive', status: 'loaded' });