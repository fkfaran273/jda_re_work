'use strict';
/* ksdump8.js - THE extraction: libpuresoftkeymasterdevice (inside keystore2)
   computes HMAC via libcrypto. Hook HMAC_Init_ex -> raw key2 bytes,
   HMAC_Update/Final -> message + H. Also EVP_Decrypt* -> blob plaintext. */
var LIBC = 'libcrypto.so';
var MAXE = 300;
var n = 0;
function res(nm) {
  /* enumerate-based: reliable across frida versions */
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf('libcrypto.so') < 0) continue;
    var ex;
    try { ex = mods[i].enumerateExports(); } catch (e) { continue; }
    for (var j = 0; j < ex.length; j++) {
      if (ex[j].name === nm) return ex[j].address;
    }
  }
  try { return Module.getExportByName(LIBC, nm); } catch (e) { }
  try { return Module.findExportByName(LIBC, nm); } catch (e) { }
  return null;
}
function looksLikePtr(v) {
  try { return !v.isNull() && Process.findRangeByAddress(v) !== null; }
  catch (e) { return false; }
}
function brief(v, len) {
  try {
    var b = new Uint8Array(v.readByteArray(len));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return 'ERR'; }
}
function hook(name, onEnterFn) {
  var p = res(name);
  send({ t: 'sym', name: name, addr: p ? p.toString() : null });
  if (!p) return;
  try {
    Interceptor.attach(p, { onEnter: onEnterFn });
    send({ t: 'hooked', name: name });
  } catch (e) { send({ t: 'err', msg: name + ': ' + e }); }
}
/* HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl) */
hook('HMAC_Init_ex', function (args) {
  if (n++ > MAXE) return;
  var key = args[1], klen = args[2].toInt32();
  send({ t: 'hmac_key', klen: klen,
         key: (klen > 0 && klen < 129 && looksLikePtr(key)) ? brief(key, klen) : 'n/a',
         hex64: looksLikePtr(key) ? brief(key, 64) : 'n/a' });
});
/* HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len) */
hook('HMAC_Update', function (args) {
  if (n > MAXE) return;
  var d = args[1], l = args[2].toInt32();
  send({ t: 'hmac_upd', len: l,
         data: (l > 0 && l < 4097 && looksLikePtr(d)) ? brief(d, l) : 'n/a' });
});
/* HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) */
hook('HMAC_Final', function (args) {
  if (n > MAXE) return;
  var o = args[1];
  send({ t: 'hmac_final_pre', out: looksLikePtr(o) ? brief(o, 32) : 'n/a' });
  this.out = o;
  try {
    var lp = args[2];
    if (looksLikePtr(lp)) this.len = lp.readU32();
  } catch (e) { this.len = 32; }
  var self = this;
  setTimeout(function () {
    send({ t: 'hmac_final', out: looksLikePtr(self.out) ? brief(self.out, 32) : 'n/a' });
  }, 0);
});
/* EVP_DecryptInit_ex(ctx, type, impl, key, iv) -> x3 key, x4 iv */
hook('EVP_DecryptInit_ex', function (args) {
  if (n > MAXE) return;
  var key = args[3], iv = args[4];
  send({ t: 'dec_init',
         key: looksLikePtr(key) ? brief(key, 32) : 'n/a',
         iv: looksLikePtr(iv) ? brief(iv, 16) : 'n/a' });
});
/* EVP_DecryptUpdate(ctx, out, outl, in, inl) -> x1 out, x3 in, x4 inl */
hook('EVP_DecryptUpdate', function (args) {
  if (n > MAXE) return;
  var out = args[1], inp = args[3], l = args[4].toInt32();
  send({ t: 'dec_upd', len: l,
         inp: (l > 0 && l < 2049 && looksLikePtr(inp)) ? brief(inp, l) : 'n/a',
         outp: looksLikePtr(out) ? brief(out, 64) : 'n/a' });
});
/* EVP_DigestUpdate(ctx, data, len) - pure-soft keymaster may implement HMAC
   via digest: first update = key XOR 0x36 (ipad) => key recoverable. */
hook('EVP_DigestUpdate', function (args) {
  if (n++ > MAXE) return;
  var d = args[1], l = args[2].toInt32();
  send({ t: 'digest_upd', len: l,
         data: (l > 0 && l < 4097 && looksLikePtr(d)) ? brief(d, l) : 'n/a' });
});
/* EVP_DigestInit_ex(ctx, type, engine) - mark a fresh digest */
hook('EVP_DigestInit_ex', function (args) {
  if (n > MAXE) return;
  send({ t: 'digest_init', type: args[1].toString() });
});
send({ t: 'ready' });