import Java from 'frida-java-bridge';
/* ks_hmac2.js - app-side: compute HMAC-SHA256 with the app's own keystore key2,
   with per-step diagnostics. The keystore2 hook captures the raw key bytes. */
function hex(a) {
  var s = '';
  for (var i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
  return s;
}
function go() {
  var Mac, S, k;
  function T(lbl, o) {
    try { send({ t: 'step', s: lbl, ty: typeof o }); } catch (e) { }
  }
  try {
    var KG = Java.use('javax.crypto.KeyGenerator');
    var KGPS = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
    Mac = Java.use('javax.crypto.Mac');
    S = Java.use('java.lang.String');
    T('KG', KG); T('KG.getInstance', KG.getInstance);
    T('KG.getInstance.overload', KG.getInstance && KG.getInstance.overload);
    T('KGPS', KGPS); T('KGPS.$new', KGPS.$new);
    var spec = KGPS.$new('k2probe', 4).build();
    T('spec', spec);
    var kg = KG.getInstance.overload('java.lang.String', 'java.lang.String').call(
      KG, 'HmacSHA256', 'AndroidKeyStore');
    T('kg', kg); T('kg.init', kg.init); T('kg.init.overload', kg.init.overload);
    kg.init.overload('java.security.spec.AlgorithmParameterSpec').call(kg, spec);
    T('kg.generateKey', kg.generateKey);
    k = kg.generateKey();
    send({ t: 'step', s: 'generated_ok' });
  } catch (e) {
    send({ t: 'err', msg: 'gen: ' + e });
    return;
  }
  function macOf(msg) {
    var m = Mac.getInstance('HmacSHA256');
    m.init.overload('java.security.Key').call(m, k);
    var d = S.$new(msg).getBytes('UTF-8');
    return hex(m.doFinal(d));
  }
  try { send({ t: 'mac', msg: 'PROBE-KEY2-MESSAGE', hex: macOf('PROBE-KEY2-MESSAGE') }); }
  catch (e) { send({ t: 'mac_err', e: String(e) }); }
  try { send({ t: 'mac2', msg: '{"a":"b"}', hex: macOf('{"a":"b"}') }); }
  catch (e) { send({ t: 'mac2_err', e: String(e) }); }
}
Java.perform(go);