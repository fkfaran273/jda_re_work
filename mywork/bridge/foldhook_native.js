/*
 * foldhook_native.js — NATIVE-ONLY adj9 seed/#10 capture (no Java bridge).
 *
 * Groups, per signing (nSign entry -> leave), on one thread:
 *   S        = low LE u32 of get8random(out[8])        @ base+0x13e0e4
 *   d10      = raw #10 claim descriptor (VA_ORDER[6])  @ base+0x100154 (x23==6)
 *   second   = wall clock at nSign entry
 *   ctx_arg  = ctx_init's seed argument (cross-check)  @ base+0x1437ec
 *   head     = VM/interpreter calls through 0x1441e4   (w1, return-site LR)
 *   whitener = every 0x144074/0x1441e4 entry          (w1, LR)
 *   clock    = gettimeofday calls in this signing      (tv_sec, tv_usec, V)
 * The 192-byte blob is logged independently by the LSPosed module; pair rows
 * by `second` and verify with FinEx.
 */
'use strict';

// ---- guard bypass (proven pattern: stealth.js / seedcap skeleton) -------------
// The SDK faults in a private poisoned range and/or self-kills when it detects
// instrumentation. Swallow the poisoned fault and block native self-kill so the
// process survives long enough to sign.
Process.setExceptionHandler(function (details) {
  var astr = details.address ? details.address.toString() : '0x0';
  var a = parseInt(astr, 16);
  var poisoned = astr.indexOf('0x600') === 0 && !isNaN(a) &&
                 a >= 0x600000000000 && a <= 0x700000000000;
  if (!poisoned) return false;
  try { details.context.pc = details.context.lr; } catch (e) {}
  return true;
});
try {
  // Frida 17 removed Module.findExportByName; use the module-object API with a
  // fallback to the legacy call so the self-kill guard still installs.
  function findExport(name) {
    try {
      var m = Process.getModuleByName('libc.so');
      if (m && m.getExportByName) return m.getExportByName(name);
    } catch (e) {}
    try { return Module.findExportByName('libc.so', name); } catch (e) {}
    return null;
  }
  var pthreadExit = findExport('pthread_exit');
  var exitPtr = findExport('exit');
  var killPtr = findExport('kill');
  var tgkillPtr = findExport('tgkill');
  if (exitPtr) {
    Interceptor.replace(exitPtr, new NativeCallback(function (code) {
      // Clean thread exit instead of killing the process (proven pattern).
      if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
    }, 'void', ['int']));
  }
  if (killPtr) {
    var origKill = new NativeFunction(killPtr, 'int', ['int', 'int']);
    Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
      if (pid === Process.id) return 0;
      return origKill(pid, sig);
    }, 'int', ['int', 'int']));
  }
  if (tgkillPtr) {
    var origTg = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
    Interceptor.replace(tgkillPtr, new NativeCallback(function (tgid, tid, sig) {
      if (tgid === Process.id && (sig === 9 || sig === 6)) return 0;
      return origTg(tgid, tid, sig);
    }, 'int', ['int', 'int', 'int']));
  }
} catch (e) { send({ type: 'guard_err', error: String(e) }); }
// -----------------------------------------------------------------------------

var base = null, installed = false, nextId = 1;
var LOG = [];
var stack = Object.create(null);   // tid -> [rec]
var clockHooked = false;
// VM descriptor iteration order (VA_ORDER): iteration index -> descriptor id
var VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3];

function emit(o) { o.t = Date.now(); LOG.push(o); try { send(o); } catch (e) {} if (LOG.length > 4000) LOG.splice(0, 2000); }
function tid() { return Process.getCurrentThreadId(); }
function top(t) { var s = stack[t]; return (s && s.length) ? s[s.length - 1] : null; }
function hexptr(p, n) {
  try { if (p === null || p.isNull()) return null;
    return Array.prototype.map.call(new Uint8Array(p.readByteArray(n)), function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');
  } catch (e) { return 'ERR:' + e; }
}
function findBase() {
  var m = Process.findModuleByName('libsigner.so'); if (m) return m.base;
  var all = Process.enumerateModules();
  for (var i = 0; i < all.length; i++) if (all[i].name.indexOf('libsigner') >= 0) return all[i].base;
  return null;
}
function off(addr) {
  if (base === null) return null;
  try { return '0x' + addr.sub(base).toString(16); } catch (e) { return null; }
}
function installClock() {
  if (clockHooked) return true;
  var p = Module.findExportByName('libc.so', 'gettimeofday');
  if (!p) return false;
  try {
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.rec = top(tid());
        if (!this.rec) return;
        this.tv = args[0];
        this.lr = this.context.lr;
      },
      onLeave: function () {
        var rec = this.rec; if (!rec || !this.tv) return;
        try {
          var sec = Number(this.tv.readS64()) >>> 0;
          var usec = Number(this.tv.add(8).readS64()) >>> 0;
          rec.clock.push({tv_sec: sec, tv_usec: usec, V: sec ^ usec,
                          return_site: off(this.lr)});
        } catch (e) {}
      }
    });
    clockHooked = true;
    emit({type: 'clock_ready', address: p.toString()});
    return true;
  } catch (e) {
    emit({type: 'clock_hook_err', error: String(e)});
    return false;
  }
}

function installNative() {
  if (installed) return true;
  var b = findBase(); if (!b) return false;
  base = b; installed = true;
  emit({ type: 'base', base: b.toString() });

  var NSIGN = 0xdb1cc, GET8 = 0x13e0e4, CTX_INIT = 0x1437ec, DESC = 0x100154;

  Interceptor.attach(b.add(NSIGN), {
    onEnter: function () {
      var t = tid();
      var rec = { sign_id: nextId++, tid: t, second: Math.floor(Date.now() / 1000), S: null, ctx_arg: null, d10: null, desc: {}, head: [], whitener: [], clock: [] };
      if (!stack[t]) stack[t] = [];
      stack[t].push(rec);
    },
    onLeave: function () {
      var t = tid(); var s = stack[t]; if (!s || !s.length) return;
      var rec = s.pop();
      emit({ type: 'sign_row', sign_id: rec.sign_id, tid: rec.tid, second: rec.second,
             S: rec.S, ctx_arg: rec.ctx_arg, ctx_match: (rec.S === rec.ctx_arg),
             d10_len: rec.d10 ? rec.d10.length / 2 : null, d10_hex: rec.d10,
             desc: rec.desc, head: rec.head, whitener: rec.whitener, clock: rec.clock });
    }
  });

  Interceptor.attach(b.add(GET8), {
    onEnter: function (args) { this.out = args[0]; this.rec = top(tid()); },
    onLeave: function () {
      var rec = this.rec; if (!rec) return;
      try { rec.S = this.out.readU32() >>> 0; } catch (e) {}
    }
  });

  Interceptor.attach(b.add(CTX_INIT), {
    onEnter: function (args) { var rec = top(tid()); if (rec) { try { rec.ctx_arg = args[1].toUInt32() >>> 0; } catch (e) {} } }
  });

  Interceptor.attach(b.add(DESC), {
    onEnter: function () {
      var rec = top(tid()); if (!rec) return;
      var iter = this.context.x23.toInt32();
      if (iter < 0 || iter >= VA_ORDER.length) return;
      var did = VA_ORDER[iter];                        // descriptor id for this slot
      try {
        var node = this.context.x27, w0 = node.readU32() >>> 0;
        var data = node.add(8).readPointer();
        var len = 4 * (w0 >>> 2) + (w0 & 3);
        if (len < 0 || len > (1 << 20)) return;
        var hx = hexptr(data, len);
        rec.desc[did] = { iter: iter, w0: w0, lenDwords: w0 >>> 2, length: len, hex: hx };
        if (did === 10) rec.d10 = hx;                  // keep the #10 shorthand
      } catch (e) {}
    }
  });

  // The VM tail-call sites enter at 0x1441e4.  Each invocation overwrites one
  // of d0[0..11], so this ordered list is the complete per-signing head.
  Interceptor.attach(b.add(0x1441e4), {
    onEnter: function (args) {
      var rec = top(tid()); if (!rec) return;
      var item = { w1: args[1].toUInt32() >>> 0, return_site: off(this.context.lr) };
      rec.head.push(item);
      rec.whitener.push({entry: '0x1441e4', w1: item.w1, return_site: item.return_site});
    }
  });

  // The ordinary materializer and all 12 tail calls converge here.  Keep this
  // full trace too; grouping by the call entry disambiguates the ordinary 72.
  Interceptor.attach(b.add(0x144074), {
    onEnter: function (args) {
      var rec = top(tid()); if (!rec) return;
      rec.whitener.push({entry: '0x144074', w1: args[1].toUInt32() >>> 0,
                         return_site: off(this.context.lr)});
    }
  });

  installClock();
  emit({ type: 'native_ready', base: b.toString() });
  return true;
}

function tick() { if (!installNative()) setTimeout(tick, 120); }
setTimeout(tick, 80);

rpc.exports = {
  events: function () { return LOG; },
  rows: function () { return LOG.filter(function (e) { return e.type === 'sign_row' && e.S !== null && e.d10_hex; }); },
  clockHooked: function () { return clockHooked; },
  base: function () { return base ? base.toString() : null; },
  installed: function () { return installed; }
};
