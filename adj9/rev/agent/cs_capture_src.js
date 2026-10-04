/* cs_capture.js - capture creditsea's adj9 signing.
 *
 * creditsea's sig SDK lives at com.adjust.sdk.sig.755f89ae93acbe52c30f8a09.*
 * (obfuscated), but NativeLibHelper is the stable JNI facade. We also hook:
 *   - javax.crypto.Mac.doFinal / update  -> the canonical string + H
 *   - android.util.Base64.encodeToString -> the blob b64
 *   - the Signer's sign() if reachable
 */
'use strict';

import Java from 'frida-java-bridge';

var OUT = { canonical: null, h: null, blobB64: null, hdr: null, map: null, err: [] };

function b64(bytes) {
  try {
    var B = Java.use('android.util.Base64');
    return B.encodeToString(bytes, 2);
  } catch (e) { return null; }
}

function install() {
  try {
    Java.perform(function () {
      var Mac = Java.use('javax.crypto.Mac');
      Mac.doFinal.overload('[B').implementation = function (inp) {
        var out = this.doFinal(inp);
        try {
          OUT.h = b64(out);
          // the input IS the canonical string
          var S = Java.use('java.lang.String');
          OUT.canonical = S.$new(inp, 'UTF-8').toString();
          send({ type: 'canonical', value: OUT.canonical });
          send({ type: 'H', value: OUT.h });
        } catch (e) { OUT.err.push('doFinal:' + e); }
        return out;
      };
      send({ type: 'log', note: 'Mac hook installed' });

      // NativeLibHelper.nSign -> blob
      try {
        Java.enumerateClassLoaders({
          onMatch: function (loader) {
            try {
              var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
              NLH.a.overloads.forEach(function (o) {
                o.implementation = function () {
                  var r = o.apply(this, arguments);
                  try {
                    if (r !== null && r.length === 192) {
                      OUT.blobB64 = b64(r);
                      send({ type: 'blob', len: r.length, b64: OUT.blobB64 });
                    }
                  } catch (e) { }
                  return r;
                };
              });
              send({ type: 'log', note: 'NLH hooked' });
            } catch (e) { }
          },
          onComplete: function () { }
        });
      } catch (e) { OUT.err.push('nlh:' + e); }

      // Base64 of the blob/header - catch header strings
      try {
        var B = Java.use('android.util.Base64');
        B.encodeToString.overload('[B', 'int').implementation = function (b, f) {
          var r = this.encodeToString(b, f);
          try {
            if (r && r.length > 200 && r.indexOf('Signature') >= 0) {
              OUT.hdr = r;
              send({ type: 'header', value: r });
            }
          } catch (e) { }
          return r;
        };
      } catch (e) { OUT.err.push('b64:' + e); }
    });
  } catch (e) { OUT.err.push('perform:' + e); }
}

rpc.exports = {
  start: function () { install(); return OUT; },
  dump: function () { return OUT; }
};

send({ type: 'cs', status: 'loaded' });
