'use strict';
/* ksdump.js - attach to keystore2 (root) and dump the AES-GCM key-blob unwrap:
   the storage/AES key, IV, ciphertext, and the PLAINTEXT (raw key material).
   keystore2 has no anti-frida guard (unlike libsigner.so). */
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
function dumpPtr(v, n) {
  try { return hexdump(v, { length: n, ansi: false }); }
  catch (e) { return 'ERR ' + e; }
}
/* our key2 blob's envelope: only dump when we see it (keeps keystore2 fast) */
var IV = [0xb5, 0x72, 0x3b, 0xa1, 0x63, 0xb4, 0x9c, 0xa6,
          0xae, 0x07, 0xbc, 0x4f, 0x84, 0x1c, 0xa8, 0xfa];
var CT = [0x4f, 0x8c, 0x85, 0x46, 0x70, 0xfd, 0x3d, 0x54, 0xb3, 0x46, 0xcb, 0x9b,
          0x4d, 0xa4, 0x40, 0x09, 0x52, 0x81, 0x5f, 0x48, 0x69, 0xbd, 0x5f, 0xcb,
          0xf1, 0xc4, 0x9e, 0x57, 0x68, 0x34, 0x42, 0x64];
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
function relevant(ctx) {
  for (var i = 0; i < 8; i++) {
    var v = ctx['x' + i];
    if (!looksLikePtr(v)) continue;
    if (hasBytes(v, IV, 600) || hasBytes(v, CT, 600)) return true;
  }
  return false;
}
function snap(ctx, n) {
  var out = [];
  for (var i = 0; i < 8; i++) {
    var v = ctx['x' + i];
    out.push('x' + i + '=' + v);
    if (looksLikePtr(v)) out.push(dumpPtr(v, n));
  }
  return out.join('\n');
}

['AES_gcm_decrypt', 'AES_gcm_encrypt'].forEach(function (name) {
  var p = found[name];
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.rel = relevant(this.context);
        if (this.rel) send({ t: 'gcm', fn: name, phase: 'enter', regs: snap(this.context, 128) });
      },
      onLeave: function (retval) {
        if (this.rel) send({ t: 'gcm', fn: name, phase: 'leave', ret: retval.toString(),
                             regs: snap(this.context, 128) });
      }
    });
    send({ t: 'hooked', name: name });
  } catch (e) { send({ t: 'err', msg: name + ': ' + e }); }
});

send({ t: 'ready' });
