import Java from 'frida-java-bridge';
/* ks_hmac.js - run IN THE APP: perform an AndroidKeyStore HMAC-SHA256 with the
   app's own "key2" alias. This forces the soft KeyMint (inside keystore2) to
   use key2's raw bytes, which the keystore2 hook captures. */
function hex(a) {
  var s = '';
  for (var i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
  return s;
}
function go() {
  var K;
  try {
    var KeyStore = Java.use('java.security.KeyStore');
    var Mac = Java.use('javax.crypto.Mac');
    var S = Java.use('java.lang.String');
    var ks = KeyStore.getInstance('AndroidKeyStore');
    ks.load(null);
    var names = [];
    try {
      var en = ks.aliases();
      while (en.hasMoreElements()) names.push(String(en.nextElement()));
    } catch (e) { names.push('enum_err:' + e); }
    send({ t: 'step', s: 'aliases', v: names.join(','),
           ty: typeof ks.getKey + '/' + typeof ks.aliases + '/' + typeof Mac.getInstance });
    K = ks.getKey.overload('java.lang.String',
                           'java.security.KeyStore$ProtectionParameter')；
  } catch (e) {
    send({ t: 'err', msg: 'stage1: ' + e });
    return;
  }
}
    var k = null;
    try {
      k = ks.getKey('key2', null);
    } catch (e1) {
      try {
        k = ks.getKey.overload('java.lang.String',
          'java.security.KeyStore$ProtectionParameter').call(ks, 'key2', null);
      } catch (e2) { send({ t: 'getkey_err', e1: String(e1), e2: String(e2) }); }
    }
    if (k === null || k === undefined) {
      /* generate key2 in this (the app's) namespace so we can read its bytes */
      try {
        var KG = Java.use('javax.crypto.KeyGenerator');
        var KGPS = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
        var kg = KG.getInstance('HmacSHA256', 'AndroidKeyStore');
        kg.init(KGPS.$new('key2', 4).build());
        kg.generateKey();
        k = ks.getKey('key2', null);
        send({ t: 'generated', ok: k !== null });
      } catch (eG) { send({ t: 'gen_err', e: String(eG) }); }
    }
    if (k === null || k === undefined) { send({ t: 'err', msg: 'no key2' }); return; }
    send({ t: 'key', cls: String(k.getClass()),
           alg: String(k.getAlgorithm()), fmt: String(k.getFormat()) });
    try { send({ t: 'enc', e: String(k.getEncoded()) }); }
    catch (e) { send({ t: 'enc_err', e: String(e) }); }
    var m = Mac.getInstance('HmacSHA256');
    try { m.init(k); }
    catch (e) { m.init.overload('java.security.Key').call(m, k); }
    var data = S.$new('PROBE-KEY2-MESSAGE').getBytes('UTF-8');
    var out = m.doFinal(data);
    send({ t: 'mac', msg: 'PROBE-KEY2-MESSAGE', hex: hex(out) });
    var m2 = Mac.getInstance('HmacSHA256');
    try { m2.init(k); }
    catch (e) { m2.init.overload('java.security.Key').call(m2, k); }
    var d2 = S.$new('{"a":"b"}').getBytes('UTF-8');
    var o2 = m2.doFinal(d2);
    send({ t: 'mac2', msg: '{"a":"b"}', hex: hex(o2) });
  } catch (e) {
    send({ t: 'err', msg: String(e) });
  }
}
Java.perform(go);