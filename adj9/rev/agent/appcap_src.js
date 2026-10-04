/* appcap_src.js - capture the APP'S OWN signing (not our own nlh.a call).

Our own invocation was proven incomplete (no 5-word #9 stream, slice 122). The
golden ground truth came from the app signing its own request, so this agent just
arms the planes and waits for the SDK to sign:
  - EMIT 0x146ed8  (builder writes descriptors + the VM writes the output)
  - LENQ 0x147304  (reads)
  - Java NLH.a     (the returned 192-byte blob, via the proven whcap6-style hook)
rpc: start() arms, stop() disarms and persists app_dump.json on the device.
*/
'use strict';

import Java from 'frida-java-bridge';

var EMITS = [], LENQ = [], BLOBS = [];
var armed = false, hooked = false, CAP = 400000;
var javaTimer = null;
var autoTimer = null;
var dumped = false;

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
  var raisePtr = findExp('libc.so', 'raise');
  var killpgPtr = findExp('libc.so', 'killpg');
  var killPtr = findExp('libc.so', 'kill');
  var tgkillPtr = findExp('libc.so', 'tgkill');
  function die(code, who) {
    send({ type: 'block', note: who + '(' + code + ')' });
    if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
  }
  if (raisePtr) {
    Interceptor.replace(raisePtr, new NativeCallback(function (sig) {
      send({ type: 'block', note: 'libc.raise(' + sig + ')' });
      return 0;
    }, 'int', ['int']));
  }
  if (killpgPtr) {
    Interceptor.replace(killpgPtr, new NativeCallback(function (pgrp, sig) {
      send({ type: 'block', note: 'libc.killpg(' + pgrp + ',' + sig + ')' });
      return 0;
    }, 'int', ['int', 'int']));
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

function hookPlanes() {
  if (hooked) return 'already';
  var b = libBase();
  if (!b) return 'no-libsigner';
  try {
    Interceptor.attach(b.add(0x146ed8), {
      onEnter: function (a) {
        if (!armed || EMITS.length > CAP) return;
        try { EMITS.push([a[1].toInt32() >>> 0, a[2].toInt32() >>> 0, a[3].toInt32() >>> 0]); } catch (e) { }
      }
    });
    Interceptor.attach(b.add(0x147304), {
      onEnter: function (a) {
        if (!armed) return;
        this.on = true;
        try { this.st = a[0].toString(); this.nn = a[1].toInt32() >>> 0; } catch (e) { this.on = false; }
      },
      onLeave: function (r) {
        if (!this.on || !armed || LENQ.length > CAP) return;
        try { LENQ.push([this.st, this.nn, r.toInt32() >>> 0]); } catch (e) { }
      }
    });
    hooked = true;
    return b.toString();
  } catch (e) { return 'err:' + e; }
}

function hookJavaBlob() {
  if (javaTimer) return 'already';
  javaTimer = setInterval(function () {
    try {
      Java.perform(function () {
        var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
        clearInterval(javaTimer); javaTimer = null;
        NLH.a.overloads.forEach(function (o) {
          try {
            o.implementation = function () {
              var r = o.apply(this, arguments);
              try {
                if (r && r.length === 192) {
                  var B64 = Java.use('android.util.Base64');
                  BLOBS.push(B64.encodeToString(r, 2));
                }
              } catch (e2) { }
              return r;
            };
          } catch (e3) { }
        });
        send({ type: 'log', note: 'java blob hook installed' });
      });
    } catch (e) { }
  }, 300);
  return 'arming';
}

/* Write the plane to the device file. Used by flush(), stop() and the
 * AUTO-FLUSH timer. NATIVE file I/O (libc fopen/fwrite) -- no Java.perform,
 * because the guard tends to kill the process right around the first Java
 * hook install, and this keeps the flush path as short as possible. */
var DUMP_PATH = '/sdcard/Android/data/com.penti.app/files/app_dump.json';

function writeDump() {
  var res = { ok: false, nemit: EMITS.length, nlenq: LENQ.length, nblobs: BLOBS.length };
  try {
    var fopen = new NativeFunction(Module.getGlobalExportByName('fopen'), 'pointer',
                                   ['pointer', 'pointer']);
    var fwrite = new NativeFunction(Module.getGlobalExportByName('fwrite'), 'ulong',
                                    ['pointer', 'ulong', 'ulong', 'pointer']);
    var fclose = new NativeFunction(Module.getGlobalExportByName('fclose'), 'int',
                                    ['pointer']);
    var o = { nemit: EMITS.length, nlenq: LENQ.length, blobs: BLOBS,
              emits: EMITS, lenq: LENQ };
    var json = JSON.stringify(o);
    var fp = fopen(Memory.allocUtf8String(DUMP_PATH), Memory.allocUtf8String('wb'));
    if (fp.isNull()) { res.err = 'fopen-failed'; return res; }
    var buf = Memory.allocUtf8String(json);
    var n = fwrite(buf, 1, json.length, fp);
    fclose(fp);
    res.ok = n === json.length;
    res.dump = DUMP_PATH;
    res.bytes = n;
    dumped = true;
  } catch (e) { res.err = '' + e; }
  return res;
}

rpc.exports = {
  start: function () {
    EMITS = []; LENQ = []; BLOBS = [];
    var hk = hookPlanes();
    var jb = hookJavaBlob();
    armed = true;
    /* auto-flush: independent of the host channel, so a SIGKILL cannot lose
     * the capture. Threshold is well below a full signing (192 emits) but
     * above the noise of a non-signing burst. */
    if (autoTimer === null) {
      autoTimer = setInterval(function () {
        try {
          if (!dumped && EMITS.length > 300) {
            var r = writeDump();
            send({ type: 'autoflush', note: 'nemit=' + EMITS.length + ' ok=' + r.ok });
          }
        } catch (e) { }
      }, 200);
    }
    return { ok: true, hk: hk, jb: jb, auto: true };
  },
  /* in-memory only: make the next resume count as a NEW session so the SDK
   * actually signs. Nothing is written to disk, so the install/attribution
   * state is untouched. */
  forceSession: function () {
    var out = { ok: false };
    try {
      Java.perform(function () {
        var Adjust = Java.use('com.adjust.sdk.Adjust');
        var names = [];
        try {
          Adjust.setSessionInterval(1);
          names.push('setSessionInterval(1)');
        } catch (e1) { names.push('setSessionInterval err ' + e1); }
        try {
          Adjust.setMinTimeBetweenSessions(1);
          names.push('setMinTimeBetweenSessions(1)');
        } catch (e2) { names.push('minTime err ' + e2); }
        try {
          Adjust.onResume();
          names.push('onResume()');
        } catch (e3) { names.push('onResume err ' + e3); }
        out.ok = true;
        out.calls = names;
      });
    } catch (e) { out.err = '' + e; }
    return out;
  },
  status: function () {
    return { armed: armed, nemit: EMITS.length, nlenq: LENQ.length, nblob: BLOBS.length };
  },
  /* Write the capture as soon as a signing has clearly happened: the app's guard
   * can kill the process before stop() is reached (observed), so do not wait. */
  flush: function () {
    var res = { ok: false, nemit: EMITS.length, nlenq: LENQ.length, nblobs: BLOBS.length };
    try {
      Java.perform(function () {
        var Str = Java.use('java.lang.String');
        var FOS = Java.use('java.io.FileOutputStream');
        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var fp = ctx.getExternalFilesDir(null).getAbsolutePath() + '/app_dump.json';
        var o = { nemit: EMITS.length, nlenq: LENQ.length, blobs: BLOBS,
                  emits: EMITS, lenq: LENQ };
        var fos = FOS.$new(fp);
        fos.write(Str.$new(JSON.stringify(o)).getBytes('UTF-8'));
        fos.close();
        res.ok = true;
        res.dump = fp;
      });
      dumped = true;
    } catch (e) { res.err = '' + e; }
    return res;
  },
  stop: function () {
    armed = false;
    var res = { nemit: EMITS.length, nlenq: LENQ.length, nblobs: BLOBS.length, dump: null };
    try {
      Java.perform(function () {
        var Str = Java.use('java.lang.String');
        var FOS = Java.use('java.io.FileOutputStream');
        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var fp = ctx.getExternalFilesDir(null).getAbsolutePath() + '/app_dump.json';
        var o = { nemit: EMITS.length, nlenq: LENQ.length, blobs: BLOBS,
                  emits: EMITS, lenq: LENQ };
        var fos = FOS.$new(fp);
        fos.write(Str.$new(JSON.stringify(o)).getBytes('UTF-8'));
        fos.close();
        res.dump = fp;
      });
    } catch (e) { res.err = '' + e; }
    return res;
  }
};

send({ type: 'appcap', status: 'loaded' });