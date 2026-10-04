'use strict';
/* ksdump3.js - dump keystore2's AES-GCM key-blob unwrap (key + plaintext).
   Resolution: libkeystore2_crypto.so export -> GOT slot -> give up. */
var IVS = [[92, 183, 236, 24, 137, 187, 146, 135, 188, 121, 86, 247, 72, 109, 133, 216], [181, 114, 59, 161, 99, 180, 156, 166, 174, 7, 188, 79, 132, 28, 168, 250], [17, 11, 58, 21, 240, 67, 114, 1, 6, 146, 194, 249, 172, 120, 213, 119], [126, 147, 113, 167, 189, 195, 198, 104, 129, 100, 24, 202, 146, 109, 175, 33], [185, 214, 158, 76, 199, 169, 148, 247, 76, 98, 60, 177, 204, 50, 115, 20], [161, 3, 192, 229, 204, 157, 47, 140, 95, 22, 68, 100, 159, 70, 42, 94], [234, 86, 74, 161, 143, 143, 173, 224, 140, 12, 37, 122, 154, 165, 208, 246], [4, 199, 68, 130, 15, 84, 237, 244, 126, 71, 165, 79, 251, 1, 108, 112], [180, 121, 208, 142, 14, 78, 26, 179, 50, 130, 252, 170, 47, 76, 194, 251], [1, 27, 224, 6, 18, 4, 23, 212, 93, 243, 249, 177, 62, 90, 110, 79]];
var CTS = [[112, 242, 149, 194, 15, 36, 187, 81, 165, 215, 107, 184, 167, 20, 33, 187, 57, 187, 33, 192, 170, 239, 75, 27, 129, 33, 81, 140, 134, 135, 28, 125], [79, 140, 133, 70, 112, 253, 61, 84, 179, 70, 203, 155, 77, 164, 64, 9, 82, 129, 95, 72, 105, 189, 95, 203, 241, 196, 158, 87, 104, 52, 66, 100], [124, 142, 162, 110, 248, 222, 133, 2, 132, 165, 157, 105, 41, 26, 188, 12, 210, 140, 157, 151, 205, 27, 26, 199, 174, 15, 140, 8, 126, 127, 129, 151], [121, 11, 156, 51, 18, 118, 52, 224, 85, 224, 77, 193, 28, 235, 96, 16, 59, 75, 238, 31, 216, 235, 22, 57, 84, 57, 243, 11, 97, 244, 86, 67], [56, 243, 62, 34, 119, 149, 229, 19, 72, 27, 136, 179, 236, 88, 11, 93, 55, 205, 78, 51, 29, 143, 254, 220, 51, 140, 124, 6, 185, 155, 156, 219], [48, 66, 96, 152, 239, 66, 153, 44, 191, 35, 222, 3, 243, 97, 137, 199, 121, 200, 253, 207, 204, 79, 166, 10, 231, 243, 255, 138, 64, 177, 198, 9], [207, 154, 7, 31, 166, 127, 162, 86, 118, 50, 224, 115, 160, 177, 133, 7, 28, 4, 5, 207, 171, 107, 104, 121, 138, 111, 143, 207, 29, 9, 117, 243], [81, 218, 122, 254, 36, 17, 250, 168, 215, 3, 142, 4, 177, 131, 147, 212, 204, 136, 160, 157, 241, 70, 59, 28, 2, 243, 96, 60, 249, 26, 190, 197], [225, 102, 153, 27, 95, 150, 116, 65, 198, 118, 233, 4, 168, 3, 87, 144, 28, 224, 91, 42, 24, 28, 233, 153, 172, 96, 209, 114, 222, 109, 138, 239], [8, 26, 201, 239, 22, 128, 126, 120, 30, 141, 186, 156, 22, 207, 88, 132, 126, 237, 55, 94, 10, 99, 39, 217, 246, 115, 21, 25, 208, 253, 225, 215]];
var GOT = {"ECDHComputeKey": 1543352, "AES_gcm_decrypt": 1543568, "AES_gcm_encrypt": 1543576, "HKDFExtract": 1543592, "HKDFExpand": 1543600};
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