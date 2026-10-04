'use strict';
/* ksdump2.js - hook keystore2's AES-GCM unwrap and dump key material.
   IVS/CTS are injected by the runner from the LIVE key2 blob. */
var IVS = [];
var CTS = [];
var TARGETS = ['AES_gcm_decrypt', 'AES_gcm_encrypt', 'HKDFExpand',
               'HKDFExtract', 'ECDHComputeKey'];
var found = {};
TARGETS.forEach(function (name) {
  var p = null;
  try { p = Module.findExportByName(null, name); } catch (e) { }
  found[name] = p;
  send({ t: 'sym', name: name, addr: p ? p.toString() : null,
         mod: p ? Process.findModuleByAddress(p).name : null });
});
function looksLikePtr(v) {
  try { return !v.isNull() && Process.findRangeByAddress(v) !== null; }
  catch (e) { return false; }
}
function hasBytes(p, pat, n) {
  try {
    var b = new Uint8Array(p.readByteArray(n));
    for (var i = 0; i + pat.length <= b.length; i++) {
      var ok = true;
      for (var j = 0; j < pat.length; j++) { if (b[i + j] !== pat[j]) { ok = false; break; } }
      if (ok) return true;
    }
    return false;
  } catch (e) { return false; }
}
function whichPattern(ctx) {
  for (var k = 0; k < IVS.length; k++) {
    for (var i = 0; i < 8; i++) {
      var v = ctx['x' + i];
      if (!looksLikePtr(v)) continue;
      if (hasBytes(v, IVS[k], 900) || hasBytes(v, CTS[k], 900))
        return 'k' + k;
    }
  }
  return null;
}
function snap(ctx, n) {
  var out = [];
  for (var i = 0; i < 8; i++) {
    var v = ctx['x' + i];
    out.push('x' + i + '=' + v);
    if (looksLikePtr(v)) {
      try { out.push(hexdump(v, { length: n, ansi: false })); } catch (e) { }
    }
  }
  return out.join('\n');
}
['AES_gcm_decrypt', 'AES_gcm_encrypt'].forEach(function (name) {
  var p = found[name];
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.tag = whichPattern(this.context);
        if (this.tag) send({ t: 'gcm', fn: name, phase: 'enter', pat: this.tag,
                             regs: snap(this.context, 160) });
      },
      onLeave: function (retval) {
        if (this.tag) send({ t: 'gcm', fn: name, phase: 'leave', pat: this.tag,
                             ret: retval.toString(), regs: snap(this.context, 160) });
      }
    });
    send({ t: 'hooked', name: name });
  } catch (e) { send({ t: 'err', msg: name + ': ' + e }); }
});
send({ t: 'ready' });