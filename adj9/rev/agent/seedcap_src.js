import Java from 'frida-java-bridge';
/*
 * adj9 fold capture — hook the NATIVE fold machinery in libsigner.so.
 *
 * This replaces the stack/`/proc/pid/mem` scans (both structurally doomed: the
 * ctx is a transient stack buffer, not a persistent region).
 *
 * Offsets (arm64, libsigner.so 5.0.0, base = start of the r-xp mapping at APK
 * file offset 0x54000):
 *   0x13e0e4  get8random(out[8])        -> openat("/dev/urandom") + read(8)
 *   0x143794  ctx_wrapper(ctx)          -> seed = get8random()[0:4]; ctx_init(ctx,seed)
 *   0x1437ec  ctx_init(ctx, seed)       -> ctx[0]=seed, LCG state @ctx+8, ctx[0x10..0x30]
 *   0x144214  driver(ctx, words*, count) -> for i<count: fold_word(ctx, words[i])
 *   0x1441e4  fold_word(ctx, len)       -> fold16(ctx, len, search_slot(ctx))
 *
 * What we need to settle, in one shot:
 *   (1) the exact 32-bit seed            -> from get8random's out buffer
 *   (2) the exact pre/post fold ctx       -> driver enter/leave
 *   (3) the exact `words` (record masks)  -> driver arg1/arg2
 *   (4) whether H is folded in            -> compare `words`/ctx vs arg3
 * (2)+(3) alone validate the Python port: replay driver(ctx_in, words) and it
 * must equal ctx_out byte-for-byte.
 */
'use strict';

var CTXSZ = 0xE0;          // dump size; real ctx needs 0xD0
var LOG = [];
var CAPTURE = true;
var base = null;
var installed = false;

function hexptr(p, n) {
  try {
    if (p.isNull()) return null;
    return Array.prototype.map.call(new Uint8Array(p.readByteArray(n)), function (b) {
      return ('0' + (b & 0xff).toString(16)).slice(-2);
    }).join('');
  } catch (e) { return 'ERR:' + e; }
}
function emit(o) {
  o.t = Date.now();
  LOG.push(o);
  try { send(o); } catch (e) {}
  if (LOG.length > 4000) LOG.splice(0, 1000);
}

function findBase() {
  var m = Process.findModuleByName('libsigner.so');
  if (m) return m.base;
  var all = Process.enumerateModules();
  for (var i = 0; i < all.length; i++) {
    if (all[i].name.indexOf('libsigner') >= 0) return all[i].base;
  }
  return null;
}

function installNative() {
  if (installed) return true;
  var b = findBase();
  if (!b) return false;
  base = b;
  emit({ type: 'base', base: b.toString(), size: Process.findModuleByName('libsigner.so') ?
        Process.findModuleByName('libsigner.so').size : null });

  // ---- 0x13e0e4 get8random(out[8]) : the seed source
  try {
    Interceptor.attach(b.add(0x13e0e4), {
      onEnter: function (args) { this.out = args[0]; },
      onLeave: function (ret) {
        if (!CAPTURE) return;
        emit({ type: 'seed', out: hexptr(this.out, 8) });
      }
    });
  } catch (e) { emit({ type: 'hookfail', what: 'get8random', err: String(e) }); }

  // ---- 0x143794 ctx_wrapper(ctx) : fires exactly once per nSign
  try {
    Interceptor.attach(b.add(0x143794), {
      onEnter: function (args) { this.ctx = args[0]; },
      onLeave: function (ret) {
        if (!CAPTURE) return;
        emit({ type: 'ctxinit', ctx: hexptr(this.ctx, CTXSZ) });
      }
    });
  } catch (e) { emit({ type: 'hookfail', what: 'ctx_wrapper', err: String(e) }); }

  // ---- 0x100154 VM descriptor iteration : capture raw #10 (VA_ORDER[6]==#10)
  // At this instruction x27 already holds the current descriptor node and x23
  // is the iteration index. Node layout: +0x00 u32 w0, +0x04 pad, +0x08 data.
  //   len_dwords = w0>>2 ; tag = w0&3 ; raw_length = 4*len_dwords + tag
  // #10 is the raw claim-string descriptor consumed directly by FinEx.
  try {
    Interceptor.attach(b.add(0x100154), {
      onEnter: function () {
        if (!CAPTURE) return;
        var i = this.context.x23.toInt32();
        if (i !== 6) return;               // VA_ORDER[6] === descriptor #10
        try {
          var node = this.context.x27;
          var w0 = node.readU32() >>> 0;
          var data = node.add(8).readPointer();
          var len = 4 * (w0 >>> 2) + (w0 & 3);
          if (len < 0 || len > (1 << 20)) {
            emit({ type: 'desc10_err', iter: i, w0: w0, length: len });
            return;
          }
          emit({ type: 'desc10', iter: i, w0: w0, tag: w0 & 3,
                 lenDwords: w0 >>> 2, length: len, hex: hexptr(data, len) });
        } catch (e) { emit({ type: 'desc10_err', iter: i, err: String(e) }); }
      }
    });
  } catch (e) { emit({ type: 'hookfail', what: 'desc10', err: String(e) }); }

  // ---- 0x144214 driver(ctx, words*, count) : THE fold loop
  try {
    Interceptor.attach(b.add(0x144214), {
      onEnter: function (args) {
        this.ctx = args[0];
        this.words = args[1];
        this.count = args[2].toInt32();
        this.armed = CAPTURE;
        if (!this.armed) return;
        var n = Math.max(0, Math.min(this.count, 512)) * 2;
        emit({
          type: 'fold_in',
          count: this.count,
          ctx: hexptr(this.ctx, CTXSZ),
          words: n > 0 ? hexptr(this.words, n) : null
        });
      },
      onLeave: function (ret) {
        if (!this.armed) return;
        emit({ type: 'fold_out', ctx: hexptr(this.ctx, CTXSZ) });
      }
    });
  } catch (e) { emit({ type: 'hookfail', what: 'driver', err: String(e) }); }

  installed = true;
  emit({ type: 'native_ready', base: b.toString() });
  return true;
}

function installJava() {
  try {
    Java.perform(function () {
      try {
        var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
        var B64 = Java.use('android.util.Base64');
        NLH.a.overload('android.content.Context', 'java.util.LinkedHashMap', '[B', 'int')
          .implementation = function (ctx, map, hmac, sdk) {
            var arg = hmac ? B64.encodeToString(hmac, 2) : null;
            var r = this.a(ctx, map, hmac, sdk);
            emit({ type: 'nsign', sdk: sdk, argHmacB64: arg,
                   outLen: r ? r.length : 0,
                   outB64: r ? B64.encodeToString(r, 2) : null });
            return r;
          };
      } catch (e) { emit({ type: 'hookfail', what: 'NLH.a', err: String(e) }); }
      emit({ type: 'java_ready' });
    });
  } catch (e) { setTimeout(installJava, 200); }
}

function tick() {
  if (!installNative()) setTimeout(tick, 150);
}
setTimeout(function () { installJava(); tick(); }, 150);

function findSignerFactory() {
  if (typeof _signerFactory !== 'undefined' && _signerFactory) return _signerFactory;
  var loaders = [];
  try {
    Java.enumerateClassLoaders({
      onMatch: function (l) { loaders.push(l); },
      onComplete: function () {}
    });
  } catch (e) { return null; }
  for (var i = 0; i < loaders.length; i++) {
    try {
      var f = Java.ClassFactory.get(loaders[i]);
      f.use('com.adjust.sdk.sig.Signer');
      _signerFactory = f;
      return f;
    } catch (e) {}
  }
  return null;
}
var _signerFactory = null;

rpc.exports = {
  events: function () { return LOG; },
  clear: function () { LOG = []; return true; },
  capture: function (on) { CAPTURE = !!on; return CAPTURE; },
  base: function () { return base ? base.toString() : null; },
  installed: function () { return installed; },
  /* Trigger a real signing through the SDK's own entry point. */
  mint: function (obj) {
    var out = { ok: false, error: null, authorization: null, envelopeB64: null, hB64: null };
    try {
      Java.perform(function () {
        var String2 = Java.use('java.lang.String');
        var HashMap = Java.use('java.util.HashMap');
        // Mirror the proven sign_src.js mint: default classloader (we are
        // injected into the app process). Fall back to a loader sweep if the
        // default one cannot resolve Signer.
        var Signer = null;
        try { Signer = Java.use('com.adjust.sdk.sig.Signer'); }
        catch (e) { var f = findSignerFactory(); if (f) Signer = f.use('com.adjust.sdk.sig.Signer'); }
        if (!Signer) { out.error = 'Signer unresolved'; return; }
        var signer = Signer.$new();
        try { signer.onResume(); } catch (e) {}
        var act = HashMap.$new();
        Object.keys(obj.activity).forEach(function (k) { act.put(k, String2.valueOf(obj.activity[k])); });
        var glob = HashMap.$new();
        Object.keys(obj.globals).forEach(function (k) { glob.put(k, String2.valueOf(obj.globals[k])); });
        var res = HashMap.$new();
        var ctx = Java.use('android.app.ActivityThread')
                      .currentApplication().getApplicationContext();
        LOG = [];
        signer.sign.overload('android.content.Context', 'java.lang.Map',
                             'java.util.Map', 'java.util.Map')
              .call(signer, ctx, act, glob, res);
        var auth = res.get('authorization');
        out.ok = auth !== null && auth !== undefined;
        out.authorization = out.ok ? Java.cast(auth, String2).toString() : null;
        out.events = LOG;
      });
    } catch (e) {
      out.error = (e && e.message) ? e.message : String(e);
      out.stack = (e && e.stack) ? e.stack : null;
    }
    return out;
  }
};
