'use strict';
/* ksdump3.js - dump keystore2's AES-GCM key-blob unwrap (key + plaintext).
   Resolution: libkeystore2_crypto.so export -> GOT slot -> give up. */
var IVS = [[]];
var CTS = [[]];
var GOT = {};
var TARGETS = ['AES_gcm_decrypt', 'AES_gcm_encrypt', 'HKDFExpand',
               'HKDFExtract', 'ECDHComputeKey'];
function resolve(name) {
  var p = null;
  try { p = Module.getExportByName('libkeystore2_crypto.so', name); } catch (e) { }
  if (!p) { try { p = Module.getExportByName(null, name); } catch (e) { } }
  if (!p && GOT[name]) {
    try {
      var mods = Process.enumerateModules();
      var base = mods[0].base;
      for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.indexOf('keystore2') === 0 && mods[i].name.indexOf('.so') < 0) {
          base = mods[i].base; break;
        }
      }
      p = base.add(GOT[name]).readPointer();
      if (p.compare(ptr('0x10000')) < 0) p = null;
    } catch (e) { p = null; }
  }
  return p;
}
var found = {};
TARGETS.forEach(function (name) {
  var p = resolve(name);
  found[name] = p;
  send({ t: 'sym', name: name, addr: p ? p.toString() : null,
         mod: p ? (Process.findModuleByAddress(p) || {}).name : null });
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
      if (hasBytes(v, IVS[k], 1200) || hasBytes(v, CTS[k], 1200)) return 'k' + k;
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
                             regs: snap(this.context, 176) });
      },
      onLeave: function (retval) {
        if (this.tag) send({ t: 'gcm', fn: name, phase: 'leave', pat: this.tag,
                             ret: retval.toString(), regs: snap(this.context, 176) });
      }
    });
    send({ t: 'hooked', name: name });
  } catch (e) { send({ t: 'err', msg: name + ': ' + e }); }
});
send({ t: 'ready' });