'use strict';
/* ks_sweep_probe.js - app-side (UID 10350). Drives a GUARANTEED AndroidKeyStore
   HMAC with the SDK's OWN key: alias "key2" (KeyGenParameterSpec("key2", 4),
   exactly as com.adjust.sdk.sig.t1 builds it). If key2 already exists it is
   reused untouched; only if absent is it created with the SDK's spec - so the
   key we capture is the real signer key, not a probe key.

   Reports: containsAlias, key class, and the MAC from BOTH providers
   (explicit AndroidKeyStore AND the default provider) so we can see which
   path the SDK's Mac.getInstance("HmacSHA256") actually takes. */
function hex(a) {
  var s = '';
  for (var i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
  return s;
}
function go() {
  var MSGS = ['PROBE-KEY2-MESSAGE', '{"a":"b"}'];
  try {
    var Mac = Java.use('javax.crypto.Mac');
    var S = Java.use('java.lang.String');
    var KS = Java.use('java.security.KeyStore');
    var ks = KS.getInstance('AndroidKeyStore');
    ks.load(null);
    var had = ks.containsAlias('key2');
    send({ t: 'probe', step: 'keystore', containsKey2: had });

    if (!had) {
      var KG = Java.use('javax.crypto.KeyGenerator');
      var Spec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
      var spec = Spec.$new('key2', 4).build();       /* PURPOSE_SIGN, as SDK */
      var kg = KG.getInstance.overload('java.lang.String', 'java.lang.String')
        .call(KG, 'HmacSHA256', 'AndroidKeyStore');
      kg.init.overload('java.security.spec.AlgorithmParameterSpec').call(kg, spec);
      kg.generateKey();
      send({ t: 'probe', step: 'generated', alias: 'key2' });
    }
    var key = ks.getKey('key2', null);
    send({ t: 'probe', step: 'got_key', cls: key.getClass().getName() });

    function macOf(msg, provider) {
      var m = provider
        ? Mac.getInstance.overload('java.lang.String', 'java.lang.String')
          .call(Mac, 'HmacSHA256', provider)
        : Mac.getInstance('HmacSHA256');
      m.init.overload('java.security.Key').call(m, key);
      return hex(m.doFinal(S.$new(msg).getBytes('UTF-8')));
    }
    for (var i = 0; i < MSGS.length; i++) {
      var a = 'n/a', b = 'n/a';
      try { a = macOf(MSGS[i], 'AndroidKeyStore'); }
      catch (e) { a = 'ERR ' + String(e); }
      try { b = macOf(MSGS[i], null); }
      catch (e) { b = 'ERR ' + String(e); }
      send({ t: 'mac', msg: MSGS[i], ks_provider: a, def_provider: b });
    }
  } catch (e) {
    send({ t: 'err', where: 'go', e: String(e) });
  }
}
Java.perform(go);