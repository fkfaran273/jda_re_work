import Java from 'frida-java-bridge';
/* ks_probe_src.js - app-side probe that forces a GUARANTEED AndroidKeyStore
   HMAC with the SDK's own alias "key2" (spec = KeyGenParameterSpec("key2", 4),
   exactly as com.adjust.sdk.sig.t1 builds it). The key already exists in the
   keystore, so it is only ever read, never regenerated.

   Every statement is wrapped by T(label, fn) so a failure reports its own label
   plus the top stack frame - an earlier version threw "TypeError: not a function"
   with no way to tell which call was at fault.

   Frida 17 has no built-in Java global; this file must be bundled with
   frida-compile before loading from Python. */
function hex(a) {
  var s = '';
  for (var i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
  return s;
}
function go() {
  var MSGS = ['PROBE-KEY2-MESSAGE', '{"a":"b"}'];
  function step(s, v) { send({ t: 'probe', step: s, v: v }); }
  function T(label, fn) {
    try { var r = fn(); step(label + ' ok'); return r; }
    catch (e) {
      var st = String((e && e.stack) || '').split('\n').slice(0, 2).join(' | ');
      step(label + ' ERR', String(e) + '  @  ' + st);
      return undefined;
    }
  }
  var Mac = T('use Mac', function () { return Java.use('javax.crypto.Mac'); });
  var S = T('use String', function () { return Java.use('java.lang.String'); });
  var KS = T('use KeyStore', function () { return Java.use('java.security.KeyStore'); });
  var ks = T('getInstance', function () {
    return KS.getInstance.overload('java.lang.String').call(KS, 'AndroidKeyStore');
  });
  if (ks === undefined) { step('ABORT', 'no KeyStore'); return; }
  T('load', function () { return ks.load(null); });
  var had = T('containsAlias', function () {
    return ks.containsAlias.overload('java.lang.String').call(ks, 'key2');
  });
  step('had', String(had));

  /* three routes to the key; the first that works is remembered */
  var key = T('getKey(over)', function () {
    return ks.getKey.overload('java.lang.String', '[C').call(ks, 'key2', null);
  });
  if (key === undefined) {
    key = T('getKey(bare)', function () { return ks.getKey('key2', null); });
  }
  if (key === undefined) {
    key = T('getKey(static^)', function () {
      return KS.getKey.overload('java.lang.String', '[C').call(ks, 'key2', null);
    });
  }
  if (key === undefined) { step('ABORT', 'no key route'); return; }
  step('key class', T('key.getClass', function () { return key.getClass().getName(); }));

  /* THE capture: Conscrypt computed a real MAC with this key, so it must have
     obtained the raw bytes. If the key exports them, key2 is ours outright and
     the probe MAC becomes the self-validation. */
  var enc = T('getEncoded', function () { return key.getEncoded(); });
  if (enc !== undefined && enc !== null) {
    var eh = hex(enc);
    step('key_encoded', eh);
    send({ t: 'keybytes', hex: eh, len: enc.length });
  } else {
    step('key_encoded', String(enc) + ' (not exportable -> need native hook)');
  }

  /* WHICH provider/class actually computed the MAC? Mac.getInstance("HmacSHA256")
     with no provider argument resolves to whatever provider is first in the
     list, and that is where the HMAC (and therefore key2) must be. The SPI
     object is then read out of javax.crypto.Mac's private `spi` field - the
     provider alone is not enough, because the SPI subclass may override every
     method we could otherwise hook on its parent. */
  var spiName = T('probe provider', function () {
    var m = Mac.getInstance.overload('java.lang.String').call(Mac, 'HmacSHA256');
    step('default Mac provider', m.getProvider().getName());
    var f = Mac.class.getDeclaredField('spi');
    f.setAccessible(true);
    var spi = f.get.overload('java.lang.Object').call(f, m);
    var cn = spi.getClass().getName();
    step('SPI implementation', cn);
    return cn;
  });
  T('enumerate Mac providers', function () {
    var Security = Java.use('java.security.Security');
    var ps = Security.getProviders();
    for (var i = 0; i < ps.length; i++) {
      var svc = ps[i].getService.overload('java.lang.String', 'java.lang.String')
        .call(ps[i], 'Mac', 'HmacSHA256');
      if (svc !== null) {
        step('prov#' + i, ps[i].getName() + ' -> ' + svc.getClassName());
      }
    }
    return true;
  });

  /* Fallback recorder: hook every HMAC/EVP-related method of Conscrypt's JNI
     class (plus the Mac SPI classes) and log byte[] arguments, so the key is
     captured wherever it surfaces - including implementations whose BoringSSL
     is statically linked and therefore invisible to export-based hooks. */
  function hookAll(cls, name) {
    try {
      var C = Java.use(cls);
      var ms = C[name].overloads, n = 0;
      for (var i = 0; i < ms.length; i++) {
        (function (m) {
          m.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var br = [];
            for (var j = 0; j < args.length; j++) {
              var x = args[j];
              if (x === null || x === undefined) { br.push(String(x)); continue; }
              if (typeof x === 'object' && x.length !== undefined) {
                try { br.push('b[' + x.length + ']' + hex(x).slice(0, 72)); }
                catch (e) { br.push('arr?'); }
              } else { br.push(String(x)); }
            }
            send({ t: 'nc', cls: cls, m: name,
                   sig: m.argumentTypes.map(function (t) { return t.className; }).join(','),
                   a: br });
            return m.apply(this, args);
          };
          n++;
        })(ms[i]);
      }
      step('hook ' + cls + '.' + name, n + ' overloads');
    } catch (e) { step('hook ' + cls + '.' + name + ' ERR', String(e)); }
  }
  function hookNamed(cls, filter) {
    try {
      var C = Java.use(cls);
      var ms = C.class.getDeclaredMethods(), n = 0;
      for (var i = 0; i < ms.length; i++) {
        var nm = ms[i].getName().toString();
        if (filter.indexOf(nm) < 0) continue;
        hookAll(cls, nm);
        n++;
      }
      step('hookedNamed ' + cls, n + ' methods matched');
    } catch (e) { step('hookedNamed ' + cls + ' ERR', String(e)); }
  }
  hookNamed('com.android.org.conscrypt.NativeCrypto',
    ['HMAC_Init_ex', 'HMAC_Update', 'HMAC_Final', 'HMAC_CTX_new', 'HMAC_CTX_free',
     'EVP_DigestSignInit', 'EVP_DigestSignUpdate', 'EVP_DigestSignFinal',
     'EVP_DigestSign', 'EVP_MAC_init', 'EVP_MAC_update', 'EVP_MAC_final',
     'EVP_DigestInit_ex', 'EVP_DigestUpdate', 'EVP_DigestFinal_ex']);
  hookAll('com.android.org.conscrypt.OpenSSLMac', 'engineInit');
  hookAll('com.android.org.conscrypt.OpenSSLMac', 'engineUpdate');
  hookAll('com.android.org.conscrypt.OpenSSLMac', 'engineDoFinal');
  /* the real SPI subclass discovered above - hooking the parent class misses
     overridden methods entirely */
  if (spiName) {
    hookNamed(String(spiName),
      ['engineInit', 'engineUpdate', 'engineDoFinal', 'engineReset']);
  }

  function macOf(msg, provider) {
    var m = provider
      ? T('Mac.getInstance2', function () {
        return Mac.getInstance.overload('java.lang.String', 'java.lang.String')
          .call(Mac, 'HmacSHA256', provider);
      })
      : T('Mac.getInstance1', function () {
        return Mac.getInstance.overload('java.lang.String').call(Mac, 'HmacSHA256');
      });
    if (m === undefined) { return 'ERR getInstance'; }
    T('Mac.init', function () { return m.init.overload('java.security.Key').call(m, key); });
    var d = T('getBytes', function () { return S.$new(msg).getBytes('UTF-8'); });
    if (d === undefined) { return 'ERR getBytes'; }
    var out = T('doFinal', function () { return m.doFinal(d); });
    if (out === undefined) { return 'ERR doFinal'; }
    return hex(out);
  }
  for (var i = 0; i < MSGS.length; i++) {
    step('--- msg ' + i + ' ---', MSGS[i]);
    var a = macOf(MSGS[i], 'AndroidKeyStore');
    step('mac_ks_' + i, a);
    var b = macOf(MSGS[i], null);
    step('mac_def_' + i, b);
    send({ t: 'mac', msg: MSGS[i], ks_provider: a, def_provider: b });
  }
}
Java.perform(go);