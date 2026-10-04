import Java from 'frida-java-bridge';

/* main2.js — stealth phases 0+2 (from device/stealth.js) + capture + mint rpc */

var CAPTURED = { canonical: null, lastHeader: null, lastBlobLen: 0, lastHmac: null, errors: [] };

/* ---------- Phase 0: swallow the guard's poisoned SIGSEGV ---------- */
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

/* ---------- Phase 2: native self-kill blocked ---------- */
try {
  var pthreadExit = Module.findExportByName('libc.so', 'pthread_exit');
  var exitPtr = Module.findExportByName('libc.so', 'exit');
  var killPtr = Module.findExportByName('libc.so', 'kill');
  var tgkillPtr = Module.findExportByName('libc.so', 'tgkill');
  if (exitPtr) {
    Interceptor.replace(exitPtr, new NativeCallback(function (code) {
      send({ type: 'block', note: 'libc.exit(' + code + ')' });
      if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
    }, 'void', ['int']));
  }
  if (killPtr) {
    var origKill = new NativeFunction(killPtr, 'int', ['int', 'int']);
    Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
      if (pid === Process.id) { send({ type: 'block', note: 'kill(self,' + sig + ')' }); return 0; }
      return origKill(pid, sig);
    }, 'int', ['int', 'int']));
  }
  if (tgkillPtr) {
    var origTg = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
    Interceptor.replace(tgkillPtr, new NativeCallback(function (tgid, tid, sig) {
      if (tgid === Process.id && (sig === 9 || sig === 6)) {
        send({ type: 'block', note: 'tgkill(self,' + tid + ',' + sig + ')' });
        return 0;
      }
      return origTg(tgid, tid, sig);
    }, 'int', ['int', 'int', 'int']));
  }
} catch (e) { send({ type: 'log', note: 'phase2 err: ' + e }); }

function install() {
  Java.perform(function () {
    var HashMap = Java.use('java.util.HashMap');
    var Base64 = Java.use('android.util.Base64');
    var Thr = Java.use('java.lang.Thread');

    function jstack() {
      try {
        return Thr.currentThread().getStackTrace().map(function (e) {
          return e.getClassName() + '.' + e.getMethodName();
        }).join(' <- ');
      } catch (e) { return '<stack>'; }
    }

    /* Java kill primitives blocked */
    try {
      Java.use('java.lang.System').exit.implementation = function (c) {
        send({ type: 'block', note: 'System.exit(' + c + ') ' + jstack() });
      };
      Java.use('android.os.Process').killProcess.implementation = function (p) {
        send({ type: 'block', note: 'Process.killProcess(' + p + ') ' + jstack() });
      };
      Java.use('java.lang.Runtime').halt.implementation = function (c) {
        send({ type: 'block', note: 'Runtime.halt(' + c + ') ' + jstack() });
      };
    } catch (e) { CAPTURED.errors.push('killblk: ' + e); }

    /* capture: d3.a(String) = exact pre-HMAC canonical string */
    try {
      var d3 = Java.use('com.adjust.sdk.sig.d3');
      d3.a.overload('java.lang.String').implementation = function (s) {
        var v = this.a(s);
        CAPTURED.canonical = String(v);
        send({ type: 'canonical', value: CAPTURED.canonical });
        return v;
      };
    } catch (e) { CAPTURED.errors.push('d3.a: ' + e); }

    /* capture: u2.a -> finished header */
    try {
      var u2 = Java.use('com.adjust.sdk.sig.u2');
      u2.a.overload('java.util.LinkedHashMap', '[B').implementation = function (map, blob) {
        var r = this.a(map, blob);
        CAPTURED.lastHeader = r;
        CAPTURED.lastBlobLen = blob.length;
        send({ type: 'header', value: r, blobLen: blob.length });
        return r;
      };
    } catch (e) { CAPTURED.errors.push('u2.a: ' + e); }

    /* capture: t1.a = THE HMAC (msg in, H out) */
    try {
      var t1 = Java.use('com.adjust.sdk.sig.t1');
      t1.a.overload('android.content.Context', '[B').implementation = function (ctx, msg) {
        var r = this.a(ctx, msg);
        try {
          CAPTURED.lastHmac = Base64.encodeToString(r, 2);
          send({ type: 'hmac', inB64: Base64.encodeToString(msg, 2),
                 outB64: CAPTURED.lastHmac });
        } catch (e) { }
        return r;
      };
    } catch (e) { CAPTURED.errors.push('t1.a: ' + e); }

    /* capture: nSign output blob */
    try {
      var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
      NLH.a.overload('android.content.Context', 'java.util.LinkedHashMap', '[B', 'int')
        .implementation = function (ctx, map, hmac, sdk) {
          var r = this.a(ctx, map, hmac, sdk);
          if (r !== null) send({ type: 'nSign', outLen: r.length,
            b64: Base64.encodeToString(r, 2) });
          return r;
        };
    } catch (e) { CAPTURED.errors.push('NLH.a: ' + e); }

    rpc.exports = {
      health: function () {
        try {
          var Signer = Java.use('com.adjust.sdk.sig.Signer');
          return { loaded: true, hasOnResume: (typeof Signer.onResume === 'function') };
        } catch (e) { return { loaded: false, error: String(e) }; }
      },

      mint: function (obj) {
        var out = { ok: false, error: null };
        try {
          var Signer = Java.use('com.adjust.sdk.sig.Signer');
          var signer = Signer.$new();
          try { signer.onResume(); } catch (e) { }
          var act = HashMap.$new();
          Object.keys(obj.activity).forEach(function (k) { act.put(k, String(obj.activity[k])); });
          var glob = HashMap.$new();
          Object.keys(obj.globals).forEach(function (k) { glob.put(k, String(obj.globals[k])); });
          var res = HashMap.$new();
          var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          CAPTURED.canonical = null; CAPTURED.lastHeader = null; CAPTURED.lastBlobLen = 0;
          signer.sign.overload('android.content.Context', 'java.util.Map',
            'java.util.Map', 'java.util.Map').call(signer, ctx, act, glob, res);
          var auth = res.get('authorization');
          out.ok = auth !== null && auth !== undefined;
          out.authorization = out.ok ? Java.cast(auth, Java.use('java.lang.String')).toString() : null;
          out.canonical = CAPTURED.canonical;
          out.blobLen = CAPTURED.lastBlobLen;
          out.resKeys = []; out.resVals = [];
          var it = res.keySet().iterator();
          while (it.hasNext()) {
            var k = Java.cast(it.next(), Java.use('java.lang.String')).toString();
            var v = res.get(k);
            out.resKeys.push(k);
            out.resVals.push(v === null ? null : Java.cast(v, Java.use('java.lang.String')).toString());
          }
        } catch (e) {
          out.error = (e && e.message) ? e.message : String(e);
        }
        return out;
      },

      lastcapture: function () { return CAPTURED; }
    };

    send({ type: 'ready', errors: CAPTURED.errors });
  });
}

var tries = 0;
function boot() {
  try { install(); } catch (e) {
    if (++tries < 40) setTimeout(boot, 250);
    else send({ type: 'ready', errors: ['java never ready: ' + e] });
  }
}
if (Java.available !== false) setTimeout(boot, 200);
else send({ type: 'ready', errors: ['java unavailable'] });
