'use strict';
/* ks_sweep.js - load into EVERY candidate crypto process (keystore2, vendor
   keymaster HAL, credstore, ...). Auto-discovers the HMAC / digest entry
   points that exist in that process's own modules, so we no longer have to
   guess which backend actually serves AndroidKeyStore key2.

   Events (all carry the module name so the winner is unambiguous):
     hmac_key   - HMAC_Init_ex raw key bytes  <- key2 itself
     hmac_upd   - message fed to the HMAC
     hmac_final - the 32-byte MAC (= H), read after return
     hmac1shot  - one-shot HMAC() key+msg
     digest_upd - EVP_DigestUpdate (manual ipad/opad implementations)
*/
var HOOKS = ['HMAC_Init_ex', 'HMAC_Update', 'HMAC_Final', 'HMAC_CTX_new',
  'HMAC_CTX_free', 'HMAC', 'EVP_DigestInit_ex', 'EVP_DigestUpdate',
  'EVP_DigestFinal_ex', 'EVP_DigestSignInit', 'EVP_DigestSignUpdate',
  'EVP_DigestSignFinal', 'EVP_MAC_init', 'EVP_MAC_update', 'EVP_MAC_final',
  'SHA256_Init', 'SHA256_Update', 'SHA256_Final'];
var MODRE = /lib(crypto|ssl|keymaster|keymint|puresoft|km_compat|tricky|keymasterdeviceutils|keymasterutils|BoringSSL)/i;
var MAXE = 400, n = 0;

function brief(v, len) {
  try {
    var b = new Uint8Array(v.readByteArray(len));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return 'ERR'; }
}
function looksLikePtr(v) {
  try { return !v.isNull() && Process.findRangeByAddress(v) !== null; }
  catch (e) { return false; }
}

var tgt = {};
Process.enumerateModules().forEach(function (m) {
  if (!MODRE.test(m.name)) return;
  var ex;
  try { ex = m.enumerateExports(); } catch (e) { return; }
  ex.forEach(function (e) {
    if (HOOKS.indexOf(e.name) < 0) return;
    if (tgt[e.name]) return;
    tgt[e.name] = { addr: e.address, mod: m.name };
  });
});
Object.keys(tgt).forEach(function (nm) {
  send({ t: 'sym', name: nm, mod: tgt[nm].mod, addr: tgt[nm].addr.toString() });
});

function hook(nm, fn) {
  try {
    Interceptor.attach(tgt[nm].addr, { onEnter: fn });
    send({ t: 'hooked', name: nm, mod: tgt[nm].mod });
  } catch (e) { send({ t: 'err', msg: nm + ': ' + e }); }
}

if (tgt['HMAC_Init_ex']) hook('HMAC_Init_ex', function (a) {
  if (n++ > MAXE) return;
  var k = a[1], kl = a[2].toInt32();
  send({ t: 'hmac_key', mod: tgt['HMAC_Init_ex'].mod, klen: kl,
         key: (kl > 0 && kl < 129 && looksLikePtr(k)) ? brief(k, kl) : 'n/a',
         hex64: looksLikePtr(k) ? brief(k, 64) : 'n/a' });
});
if (tgt['HMAC_Update']) hook('HMAC_Update', function (a) {
  if (n > MAXE) return;
  var d = a[1], l = a[2].toInt32();
  send({ t: 'hmac_upd', mod: tgt['HMAC_Update'].mod, len: l,
         data: (l > 0 && l < 8193 && looksLikePtr(d)) ? brief(d, l) : 'n/a' });
});
if (tgt['HMAC_Final']) hook('HMAC_Final', function (a) {
  if (n > MAXE) return;
  var o = a[1];
  this.out = o;
  var self = this;
  setTimeout(function () {
    send({ t: 'hmac_final', mod: tgt['HMAC_Final'].mod,
           out: looksLikePtr(self.out) ? brief(self.out, 32) : 'n/a' });
  }, 0);
});
/* one-shot: HMAC(md, key, key_len, d, n, md_out, md_len) */
if (tgt['HMAC']) hook('HMAC', function (a) {
  if (n > MAXE) return;
  var k = a[1], kl = a[2].toInt32(), d = a[3], dl = a[4].toInt32();
  send({ t: 'hmac1shot', mod: tgt['HMAC'].mod, klen: kl,
         key: (kl > 0 && kl < 129 && looksLikePtr(k)) ? brief(k, kl) : 'n/a',
         len: dl, data: (dl > 0 && dl < 8193 && looksLikePtr(d)) ? brief(d, dl) : 'n/a' });
});
if (tgt['EVP_DigestUpdate']) hook('EVP_DigestUpdate', function (a) {
  if (n > MAXE) return;
  var d = a[1], l = a[2].toInt32();
  send({ t: 'digest_upd', mod: tgt['EVP_DigestUpdate'].mod, len: l,
         data: (l > 0 && l < 8193 && looksLikePtr(d)) ? brief(d, l) : 'n/a' });
});
send({ t: 'ready', pid: Process.id, mods: Object.keys(tgt).length });