'use strict';
/* ksdump6.js - hook libkeystore2_crypto AES_gcm_* by fixed offset.
   AOSP signature: (key, key_len, nonce, nonce_len, tag, tag_len, in, in_len, out)
   => x0 points at the AES key that opens the soft-KeyMint key blobs. */
var OFF = {};              /* {"AES_gcm_decrypt": 0x71b8, ...} injected */
var MAXE = 400;
var n = 0;
function modBase() {
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++)
    if (mods[i].name === 'libkeystore2_crypto.so') return mods[i].base;
  return null;
}
function looksLikePtr(v) {
  try { return !v.isNull() && Process.findRangeByAddress(v) !== null; }
  catch (e) { return false; }
}
function brief(v, n2) {
  try {
    var b = new Uint8Array(v.readByteArray(n2));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return 'ERR'; }
}
var base = modBase();
send({ t: 'base', addr: base ? base.toString() : null });
Object.keys(OFF).forEach(function (name) {
  if (!base) return;
  var addr = base.add(OFF[name]);
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        if (n++ > MAXE) return;
        var o = [];
        for (var i = 0; i < 8; i++) {
          var v = this.context['x' + i];
          o.push('x' + i + '=' + v + (looksLikePtr(v) ? ':' + brief(v, 64) : ''));
        }
        var sp = this.context.sp;
        var outp = null;
        try { outp = sp.readPointer(); } catch (e) { }
        o.push('out=' + outp + (outp && looksLikePtr(outp) ? ':' + brief(outp, 64) : ''));
        send({ t: 'call', fn: name, phase: 'enter', regs: o.join(' ') });
      },
      onLeave: function (retval) {
        if (n > MAXE) return;
        var o = [];
        for (var i = 0; i < 8; i++) {
          var v = this.context['x' + i];
          o.push('x' + i + '=' + v + (looksLikePtr(v) ? ':' + brief(v, 64) : ''));
        }
        var sp = this.context.sp;
        var outp = null;
        try { outp = sp.readPointer(); } catch (e) { }
        o.push('out=' + outp + (outp && looksLikePtr(outp) ? ':' + brief(outp, 64) : ''));
        send({ t: 'call', fn: name, phase: 'leave', ret: retval.toString(),
               regs: o.join(' ') });
      }
    });
    send({ t: 'hooked', name: name, addr: addr.toString() });
  } catch (e) { send({ t: 'err', msg: name + ': ' + e }); }
});
send({ t: 'ready' });