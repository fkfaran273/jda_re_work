/* writer2_src.js - catch WHO WRITES the region source struct (slice 145).
 *
 * Strategy: fast-attach agent, hooks the copy loop (0x10017c reads the 11
 * source arrays) to learn the struct addresses in THIS process, then arms
 * MemoryAccessMonitor on those pages so the NEXT signing's writes reveal the
 * writer PC. Also hooks the worker-thread trio (0x95fc4/0x962ac/0x96320) and
 * the variadic emit fn entry (0x100094) as signing boundaries.
 * Native-only: no Java bridge. Auto-flushes via libc to /sdcard every 200ms.
 */
'use strict';

var WATCH = [], SRC = [], BOUND = [], WORK = [];
var armed = false, monArmed = false, dumped = false;
var srcAddrs = [];       // unique source-array pointers seen this signing
var seenAddrs = {};      // across signings
var CAP = 20000;

Process.setExceptionHandler(function (details) {
  var astr = details.address ? details.address.toString() : '0x0';
  var a = parseInt(astr, 16);
  /* our watchpoint: fault inside the watched native range */
  if (WATCHLO !== null && a >= parseInt(WATCHLO, 16) && a < parseInt(WATCHHI, 16)) {
    var pc = '?';
    try { pc = details.context.pc.sub(BASE).toString(16); } catch (e) { }
    if (WATCH.length < CAP) WATCH.push(['fault', pc, details.address.toString()]);
    try { Memory.protect(ptr(WATCHLO), Number(BigInt(WATCHHI) - BigInt(WATCHLO)), 'rw-'); } catch (e) { }
    WREARM = true;   /* loop re-protects to '---' in 40ms */
    return true;     /* retry the faulting access now that pages are rw */
  }
  var poisoned = astr.indexOf('0x600') === 0 && !isNaN(a) &&
                 a >= 0x600000000000 && a <= 0x700000000000;
  if (!poisoned) return false;
  try { details.context.pc = details.context.lr; } catch (e) { }
  return true;
});

(function guardOff() {
  function findExp(name) {
    try { return Module.getGlobalExportByName(name); } catch (e) { }
    return null;
  }
  try {
    var raisePtr = findExp('raise');
    if (raisePtr) Interceptor.replace(raisePtr, new NativeCallback(function (sig) {
      send({ type: 'block', note: 'raise(' + sig + ')' }); return 0;
    }, 'int', ['int']));
    var exitPtr = findExp('exit');
    if (exitPtr) Interceptor.replace(exitPtr, new NativeCallback(function (c) {
      send({ type: 'block', note: 'exit(' + c + ')' });
      var pe = findExp('pthread_exit');
      if (pe) new NativeFunction(pe, 'void', ['pointer'])(ptr(0));
    }, 'void', ['int']));
    var killPtr = findExp('kill');
    if (killPtr) {
      var oK = new NativeFunction(killPtr, 'int', ['int', 'int']);
      Interceptor.replace(killPtr, new NativeCallback(function (p, s) {
        if (p === Process.id) { send({ type: 'block', note: 'kill(self)' }); return 0; }
        return oK(p, s);
      }, 'int', ['int', 'int']));
    }
    var tgkillPtr = findExp('tgkill');
    if (tgkillPtr) {
      var oT = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
      Interceptor.replace(tgkillPtr, new NativeCallback(function (p, t, s) {
        if (p === Process.id && (s === 9 || s === 6)) {
          send({ type: 'block', note: 'tgkill(self)' }); return 0;
        }
        return oT(p, t, s);
      }, 'int', ['int', 'int', 'int']));
    }
  } catch (e) { send({ type: 'log', note: 'guard err: ' + e }); }
})();

function libBase() {
  var ms = Process.enumerateModules();
  for (var i = 0; i < ms.length; i++)
    if (ms[i].path.indexOf('libsigner.so') >= 0) return ms[i].base;
  return null;
}

var BASE = null;

var WATCHLO = null, WATCHHI = null, WREARM = false;

function inWatch(a) {
  if (WATCHLO === null) return false;
  return a >= WATCHLO && a < WATCHHI;
}

function armMonitor() {
  if (WATCHLO !== null) return 'already';
  if (!BASE || srcAddrs.length === 0) return 'need-addrs';
  var lo = null, hi = null, sv;
  for (var i = 0; i < srcAddrs.length; i++) {
    sv = srcAddrs[i].toString();
    if (sv.indexOf('0xb40000') === 0) continue;   /* java heap: separate page set */
    if (lo === null || sv < lo) lo = sv;
    if (hi === null || sv > hi) hi = sv;
  }
  if (lo === null) return 'no-native-addrs';
  try {
    var loB = BigInt(ptr(lo).toString()) & 0xfffffffffffff000n;
    var hiB = (BigInt(ptr(hi).toString()) + 0x1000n) & 0xfffffffffffff000n;
    WATCHLO = '0x' + loB.toString(16);
    WATCHHI = '0x' + hiB.toString(16);
    Memory.protect(ptr(WATCHLO), Number(hiB - loB), '---');
  } catch (e) { WATCHLO = null; WATCHHI = null; return 'prot-err:' + e; }
  WREARM = false;
  send({ type: 'log', note: 'watchpoint armed ' + WATCHLO + '..' + WATCHHI });
  return 'ok ' + WATCHLO + '..' + WATCHHI;
}

/* re-protect loop: after a fault we leave pages rw for 20ms, then re-arm */
setInterval(function () {
  if (WATCHLO === null || !WREARM) return;
  WREARM = false;
  try {
    Memory.protect(ptr(WATCHLO), Number(BigInt(WATCHHI) - BigInt(WATCHLO)), '---');
  } catch (e) { }
}, 40);

function tonum(p) {
  // numeric compare helper (fits in double for heap addrs? use string compare fallback)
}

function hookAll(b) {
  BASE = b;
  try {
    Interceptor.attach(b.add(0x100094), {
      onEnter: function () {
        if (!armed || BOUND.length >= 2000) return;
        BOUND.push(['emit-fn', srcAddrs.length]);
        if (!monArmed && srcAddrs.length) { var r = armMonitor(); send({ type: 'log', note: 'monitor@entry: ' + r }); }
      }
    });
  } catch (e) { }
  try {
    Interceptor.attach(b.add(0x10017c), {
      onEnter: function () {
        if (!armed || SRC.length >= CAP) return;
        var c = this.context;
        var a = c.x8.toString();
        if (!seenAddrs[a]) { seenAddrs[a] = true; srcAddrs.push(c.x8); }
        var d0 = '?';
        try { d0 = c.x8.add(c.x22.toInt32() * 4).readU32().toString(16); } catch (e) { }
        SRC.push([a, c.x22.toString(16), d0]);
      }
    });
  } catch (e) { }
  try {
    Interceptor.attach(b.add(0x95fc4), {
      onEnter: function () { if (armed && WORK.length < CAP) WORK.push(['95fc4', 'lr', this.returnAddress.sub(b).toString(16)]); }
    });
    Interceptor.attach(b.add(0x962ac), {
      onEnter: function (a) {
        if (armed && WORK.length < CAP)
          WORK.push(['worker', this.threadId, 'x0', a[0].toString(), 'lr', this.returnAddress.sub(b).toString(16)]);
      }
    });
    Interceptor.attach(b.add(0x96320), {
      onEnter: function (a) {
        if (armed && WORK.length >= CAP) return;
        this.tag = 'workblr' + WORK.length;
        try { WORK.push(['workblr', this.threadId, 'x0', a[0].toString(), 'vt', a[0].readPointer().sub(b).toString(16), 'lr', this.returnAddress.sub(b).toString(16)]); } catch (e) { }
      },
      onLeave: function (r) {
        if (armed && WORK.length < CAP) WORK.push(['workret', this.tag || '?', r.toString()]);
      }
    });
  } catch (e) { }
  send({ type: 'log', note: 'hooks installed' });
}

var DUMP_PATH = '/sdcard/Android/data/com.penti.app/files/writer2_dump.json';
var CYC = 0;

function writeDump() {
  var res = { ok: false };
  try {
    var fopen = new NativeFunction(Module.getGlobalExportByName('fopen'), 'pointer', ['pointer', 'pointer']);
    var fwrite = new NativeFunction(Module.getGlobalExportByName('fwrite'), 'ulong', ['pointer', 'ulong', 'ulong', 'pointer']);
    var fclose = new NativeFunction(Module.getGlobalExportByName('fclose'), 'int', ['pointer']);
    var o = { watch: WATCH, src: SRC.slice(0, 400), bound: BOUND, work: WORK.slice(0, 200),
              base: BASE ? BASE.toString() : null };
    var json = JSON.stringify(o);
    var fp = fopen(Memory.allocUtf8String(DUMP_PATH.replace('.json', '_c' + CYC + '.json')), Memory.allocUtf8String('wb'));
    if (fp.isNull()) { res.err = 'fopen'; return res; }
    var buf = Memory.allocUtf8String(json);
    var n = fwrite(buf, 1, json.length, fp);
    fclose(fp);
    res.ok = (n === json.length);
    res.bytes = n;
    dumped = true;
  } catch (e) { res.err = '' + e; }
  return res;
}

rpc.exports = {
  start: function (cyc) {
    CYC = cyc || 0;
    WATCH = []; SRC = []; BOUND = []; WORK = [];
    var b = libBase();
    armed = true;
    if (b) hookAll(b);
    setInterval(function () {
      try { if (!BASE) { var b2 = libBase(); if (b2) { hookAll(b2); send({ type: 'log', note: 'hooks installed (retry)' }); } } } catch (e) { }
    }, 100);
    setInterval(function () {
      try {
        if (!dumped && (WATCH.length > 0 || SRC.length >= 11)) {
          var r = writeDump();
          if (WATCH.length && WATCH.length % 20 === 0)
            send({ type: 'af', note: 'watch=' + WATCH.length + ' ok=' + r.ok });
        }
      } catch (e) { }
    }, 200);
    return { ok: true, base: b ? b.toString() : null };
  },
  armNow: function () { return armMonitor(); },
  status: function () {
    return { watch: WATCH.length, src: SRC.length, addrs: srcAddrs.length,
             mon: (WATCHLO !== null), work: WORK.length, dumped: dumped };
  },
  flush: function () { return writeDump(); },
  forceSession: function () {
    var out = { ok: false };
    try {
      Java.perform(function () {
        try { Java.use('com.adjust.sdk.Adjust').setSessionInterval(1); } catch (e1) { }
        try { Java.use('com.adjust.sdk.Adjust').setMinTimeBetweenSessions(1); } catch (e2) { }
        try { Java.use('com.adjust.sdk.Adjust').onResume(); } catch (e3) { }
        out.ok = true;
      });
    } catch (e) { out.err = '' + e; }
    return out;
  }
};

send({ type: 'writer2', status: 'loaded' });
