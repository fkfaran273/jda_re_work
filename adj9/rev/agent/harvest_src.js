/* harvest2_src.js - v2: killguard + LAZY emit hook (resolved inside harvest()).
 * Fixes v1 failures: (a) EMIT resolved at load when libsigner.so unmapped ->
 * base 'null'; (b) app self-kill destroyed the script mid-call.
 * Exports: setpairs(p), harvest(gaid) -> {blobB64, emits[(sink,n,val)]}.
 */
'use strict';

import Java from 'frida-java-bridge';

var PAIRS = null;
var EMITS = [];
var armed = false;
var emitHooked = false;

/* ---- poisoned-SIGSEGV swallow + native self-kill block (proven main.js) ---- */
Process.setExceptionHandler(function (details) {
  var astr = details.address ? details.address.toString() : '0x0';
  var a = parseInt(astr, 16);
  var poisoned = astr.indexOf('0x600') === 0 && !isNaN(a) &&
                 a >= 0x600000000000 && a <= 0x700000000000;
  if (!poisoned) return false;
  send({ type: 'exception', note: 'EXC ' + details.type + ' addr=' + astr });
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
  var _exitPtr = findExp('libc.so', '_exit');
  var abortPtr = findExp('libc.so', 'abort');
  var killPtr = findExp('libc.so', 'kill');
  var tgkillPtr = findExp('libc.so', 'tgkill');
  if (exitPtr) {
    Interceptor.replace(exitPtr, new NativeCallback(function (code) {
      send({ type: 'block', note: 'libc.exit(' + code + ')' });
      if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
    }, 'void', ['int']));
  }
  if (_exitPtr) {
    Interceptor.replace(_exitPtr, new NativeCallback(function (code) {
      send({ type: 'block', note: 'libc._exit(' + code + ')' });
      if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
    }, 'void', ['int']));
  }
  if (abortPtr) {
    Interceptor.replace(abortPtr, new NativeCallback(function () {
      send({ type: 'block', note: 'libc.abort()' });
    }, 'void', []));
  }
  if (killPtr) {
    var origKill = new NativeFunction(killPtr, 'int', ['int', 'int']);
    Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
      if (pid === Process.id) { send({ type: 'block', note: 'kill(self)' }); return 0; }
      return origKill(pid, sig);
    }, 'int', ['int', 'int']));
  }
  if (tgkillPtr) {
    var origTg = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
    Interceptor.replace(tgkillPtr, new NativeCallback(function (tgid, tid, sig) {
      if (tgid === Process.id && (sig === 9 || sig === 6)) {
        send({ type: 'block', note: 'tgkill(self)' });
        return 0;
      }
      return origTg(tgid, tid, sig);
    }, 'int', ['int', 'int']));
  }
  send({ type: 'log', note: 'phase2 ok exit=' + !!exitPtr + ' kill=' + !!killPtr + ' tgkill=' + !!tgkillPtr });
} catch (e) { send({ type: 'log', note: 'phase2 err: ' + e }); }

var DUMPS = [];        // [{tag, va, b64}] raw memory windows
var builderHooked = false;

function b64ab(ab) {
  var u = new Uint8Array(ab), TAB = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var s = '', i;
  for (i = 0; i + 2 < u.length; i += 3) {
    var n = (u[i] << 16) | (u[i + 1] << 8) | u[i + 2];
    s += TAB[(n >> 18) & 63] + TAB[(n >> 12) & 63] + TAB[(n >> 6) & 63] + TAB[n & 63];
  }
  if (i < u.length) {
    var rem = u.length - i, m = (u[i] << 16) | (rem === 2 ? u[i + 1] << 8 : 0);
    s += TAB[(m >> 18) & 63] + TAB[(m >> 12) & 63] + (rem === 2 ? TAB[(m >> 6) & 63] : '=') + '=';
  }
  return s;
}

function libsignerBase() {
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].path.indexOf('libsigner.so') >= 0) return mods[i].base;
  }
  return null;
}

/* Builder sub_95fc4(sdk, env, &ctx, &map, &H, &status): its pointers point at the
 * structures the descriptor table is written into.  Dump a window at each. */
function hookBuilder() {
  if (builderHooked) return 'already';
  var base = libsignerBase();
  if (!base) return 'no-libsigner';
  try {
    Interceptor.attach(base.add(0x95fc4), {
      onEnter: function (args) {
        if (!armed) return;
        this.a = [args[0], args[1], args[2], args[3], args[4], args[5]];
      },
      onLeave: function (ret) {
        if (!armed) return;
        this.a.forEach(function (p, i) {
          try {
            var ab = p.readByteArray(0x2000);
            if (ab) DUMPS.push({ tag: 'arg' + i, va: p.toString(), b64: b64ab(ab) });
          } catch (e) { }
        });
        try {
          var ab2 = ret.readByteArray(0x800);
          if (ab2) DUMPS.push({ tag: 'ret', va: ret.toString(), b64: b64ab(ab2) });
        } catch (e) { }
      }
    });
    builderHooked = true;
    return base.toString();
  } catch (e) { return 'err:' + e; }
}

function hookEmit() {
  if (emitHooked) return 'already';
  var base = null;
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].path.indexOf('libsigner.so') >= 0) { base = mods[i].base; break; }
  }
  if (!base) return 'no-libsigner';
  var emitAddr = base.add(0x146ed8);
  try {
    Interceptor.attach(emitAddr, {
      onEnter: function (args) {
        if (!armed) return;
        if (EMITS.length > 400000) return;
        try {
          EMITS.push([args[1].toInt32() >>> 0, args[2].toInt32() >>> 0,
                      args[3].toInt32() >>> 0]);
        } catch (e) { }
      }
    });
    emitHooked = true;
    return base.toString();
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
        var H = Java.array('byte', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
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
        var hooked = hookEmit();
        var bhook = hookBuilder();
        var m = LH.$new();
        PAIRS.forEach(function (kv) {
          var v = kv[1];
          if (kv[0] === 'gps_adid' && gaidOverride) v = gaidOverride;
          m.put(Str.$new(kv[0]), v === null ? null : Str.$new(v));
        });
        EMITS = [];
        DUMPS = [];
        armed = true;
        var blob = nlh.a(ctx, m, H, 31);
        armed = false;
        /* NOTE: per-stream window dumps were tried here and destabilised the
         * target (script destroyed mid-call).  The arg-window dumps above are the
         * known-good configuration -- keep them, nothing else. */
        var used = [];
        PAIRS.forEach(function (kv) {
          var v = kv[1];
          if (kv[0] === 'gps_adid' && gaidOverride) v = gaidOverride;
          used.push([kv[0], v]);
        });
        var o = { blobB64: blob ? B64.encodeToString(blob, 2) : null,
                  nemits: EMITS.length, nreported: EMITS.length,
                  nsegs: 1, si: 0, ticks: Date.now(),
                  hB64: B64.encodeToString(H, 2),
                  mapPairs: used,
                  emits: EMITS };
        try { dump('harvest_out.json', o); } catch (eD) { o.dumpErr = '' + eD; }
        try { dump('dmp_out.json', { ndumps: DUMPS.length, bhook: bhook,
                                     dumps: DUMPS }); } catch (eD2) { }
        return o;
      });
      out.ok = true;
      out.emitBase = hooked;
      out.detail = r;
    } catch (e) { out.error = '' + e; }
    return out;
  }
};

send({ type: 'harvest2', status: 'loaded', emitHookedAtLoad: emitHooked });

