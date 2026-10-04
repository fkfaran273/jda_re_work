'use strict';
/* ksdump4.js - log ALL AES-GCM/HKDF/ECDH calls in keystore2 (compact), so we can
   identify the key2 blob unwrap offline. No pattern filter (avoid missing it). */
var GOT = {};
var TARGETS = ['AES_gcm_decrypt', 'AES_gcm_encrypt', 'HKDFExpand',
               'HKDFExtract', 'ECDHComputeKey'];
var MAX = 400;
var n = 0;
function resolve(name) {
  var p = null;
  try { p = Module.getExportByName('libkeystore2_crypto.so', name); } catch (e) { }
  if (!p) { try { p = Module.getExportByName(null, name); } catch (e) { } }
  return p;
}
function looksLikePtr(v) {
  try { return !v.isNull() && Process.findRangeByAddress(v) !== null; }
  catch (e) { return false; }
}
function brief(v, n2) {
  try {
    var b = new Uint8Array(v.readByteArray(n2));
    var s = '';
    for (var i = 0; i < b.length; i++) {
      s += ('0' + b[i].toString(16)).slice(-2);
    }
    return s;
  } catch (e) { return 'ERR'; }
}
function snap(ctx) {
  var out = [];
  for (var i = 0; i < 8; i++) {
    var v = ctx['x' + i];
    if (looksLikePtr(v)) out.push('x' + i + '=' + v + ':' + brief(v, 48));
    else out.push('x' + i + '=' + v);
  }
  return out.join(' ');
}
TARGETS.forEach(function (name) {
  var p = resolve(name);
  send({ t: 'sym', name: name, addr: p ? p.toString() : null });
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter: function (args) {
        if (n++ > MAX) return;
        send({ t: 'call', fn: name, phase: 'enter', regs: snap(this.context) });
      },
      onLeave: function (retval) {
        if (n > MAX) return;
        send({ t: 'call', fn: name, phase: 'leave', ret: retval.toString(),
               regs: snap(this.context) });
      }
    });
    send({ t: 'hooked', name: name });
  } catch (e) { send({ t: 'err', msg: name + ': ' + e }); }
});
send({ t: 'ready' });