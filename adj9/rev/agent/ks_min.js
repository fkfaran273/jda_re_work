'use strict';
/* ks_min.js - MINIMAL, low-overhead HMAC capture.
   Deliberately excludes the hot digest/HMAC-feed functions (EVP_DigestUpdate,
   SHA256_*) whose Interceptor overhead can stall a crypto-heavy process.

   IMPORTANT: every module's copy of each symbol is hooked. Conscrypt links
   BoringSSL statically into libjavacrypto.so, so its HMAC_* calls do NOT reach
   libcrypto.so's exported functions; de-duplicating by symbol name (an earlier
   version of this script) hooked whichever copy was enumerated first and
   therefore caught nothing. The module name is always reported so the backend
   can be identified by observation. */
var WANT = ['HMAC_Init_ex', 'HMAC_Final', 'HMAC', 'EVP_MAC_init', 'EVP_MAC_final',
  'EVP_DigestSignInit', 'EVP_DigestSignUpdate', 'EVP_DigestSignFinal',
  'EVP_DigestSign', 'EVP_DigestInit_ex', 'EVP_DigestFinal_ex', 'EVP_PKEY_derive',
  'SHA256_Init', 'SHA256_Final'];
var MODRE = /lib(crypto|ssl|javacrypto|keymaster|keymint|puresoft|km_compat|tricky|conscrypt)/i;
var MAXE = 250, n = 0;

function brief(v, len) {
  try {
    var b = new Uint8Array(v.readByteArray(len)), s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return 'ERR'; }
}
function ok(v) {
  try { return !v.isNull() && Process.findRangeByAddress(v) !== null; }
  catch (e) { return false; }
}

function mkHandler(t) {
  var nm = t.name, mod = t.mod;
  if (nm === 'HMAC_Init_ex') return function (a) {
    if (n++ > MAXE) return;
    var k = a[1], kl = a[2].toInt32();
    send({ t: 'hmac_key', via: 'HMAC_Init_ex', pid: Process.id, mod: mod, klen: kl,
           key: (kl > 0 && kl < 129 && ok(k)) ? brief(k, kl) : 'n/a',
           hex64: ok(k) ? brief(k, 64) : 'n/a' });
  };
  if (nm === 'HMAC_Final') return function (a) {
    if (n > MAXE) return;
    var o = a[1];
    setTimeout(function () {
      send({ t: 'hmac_final', pid: Process.id, mod: mod, out: ok(o) ? brief(o, 32) : 'n/a' });
    }, 0);
  };
  if (nm === 'HMAC') return function (a) {
    if (n++ > MAXE) return;
    var k = a[1], kl = a[2].toInt32(), d = a[3], dl = a[4].toInt32();
    send({ t: 'hmac_key', via: 'HMAC(1shot)', pid: Process.id, mod: mod, klen: kl,
           key: (kl > 0 && kl < 129 && ok(k)) ? brief(k, kl) : 'n/a',
           mlen: dl, msg: (dl > 0 && dl < 8193 && ok(d)) ? brief(d, dl) : 'n/a' });
  };
  if (nm === 'EVP_MAC_init') return function (a) {
    if (n++ > MAXE) return;
    var k = a[1], kl = a[2].toInt32();
    send({ t: 'hmac_key', via: 'EVP_MAC_init', pid: Process.id, mod: mod, klen: kl,
           key: (kl > 0 && kl < 129 && ok(k)) ? brief(k, kl) : 'n/a' });
  };
  if (nm === 'EVP_DigestSignInit') return function (a) {
    if (n++ > MAXE) return;
    /* (ctx, pctx, type, md, pkey): when a soft HMAC is driven through the digest
       interface the "key" is the pkey at a[4]; record its pointer + window. */
    var pk = a[4];
    send({ t: 'digsign_init', pid: Process.id, mod: mod, has_key: ok(pk),
           pkey: ok(pk) ? brief(pk, 48) : 'n/a' });
  };
  return function (a) {
    if (n++ > MAXE) return;
    send({ t: 'digest_call', pid: Process.id, mod: mod, fn: nm });
  };
}

var list = [];
Process.enumerateModules().forEach(function (m) {
  if (!MODRE.test(m.name)) return;
  var ex;
  try { ex = m.enumerateExports(); } catch (e) { return; }
  ex.forEach(function (e) {
    if (WANT.indexOf(e.name) < 0) return;
    list.push({ name: e.name, addr: e.address, mod: m.name });
  });
});
send({ t: 'mods', pid: Process.id,
       names: list.map(function (x) { return x.mod + ':' + x.name; }) });
list.forEach(function (t) {
  try {
    Interceptor.attach(t.addr, { onEnter: mkHandler(t) });
    send({ t: 'hooked', name: t.name, mod: t.mod, pid: Process.id });
  } catch (e) { send({ t: 'err', msg: t.name + '@' + t.mod + ': ' + e }); }
});
send({ t: 'ready', pid: Process.id, hooks: list.length });