/* cs_http.js - capture creditsea's Adjust HTTP request headers (Authorization). */
'use strict';
import Java from 'frida-java-bridge';

var REQS = [];

function install() {
  try {
    Java.perform(function () {
      // hook HttpURLConnection header set + connect
      try {
        var HUC = Java.use('java.net.HttpURLConnection');
        HUC.setRequestProperty.implementation = function (k, v) {
          try {
            if (k && (k.toLowerCase() === 'authorization' || k.toLowerCase() === 'client-sdk')) {
              REQS.push({ h: k.toString(), v: v ? v.toString() : null });
              send({ type: 'hdr', key: k.toString(), value: v ? v.toString() : null });
            }
          } catch (e) { }
          return this.setRequestProperty(k, v);
        };
        send({ type: 'log', note: 'HUC hook' });
      } catch (e) { send({ type: 'err', note: 'huc:' + e }); }

      // hook OkHttp Request.Builder (Headless)
      try {
        var RB = Java.use('okhttp3.Request$Builder');
        RB.addHeader.implementation = function (k, v) {
          try {
            if (k && k.toLowerCase() === 'authorization') {
              send({ type: 'hdr-ok', key: k.toString(), value: v ? v.toString() : null });
            }
          } catch (e) { }
          return this.addHeader(k, v);
        };
        send({ type: 'log', note: 'ok3 hook' });
      } catch (e) { send({ type: 'err', note: 'ok3:' + e }); }

      // is the sig SDK even present/used?
      try {
        var sig = Java.use('com.adjust.sdk.sig.NativeLibHelper');
        send({ type: 'log', note: 'NLH class present' });
      } catch (e) { send({ type: 'err', note: 'NLH absent: ' + e }); }
    });
  } catch (e) { send({ type: 'err', note: 'perform:' + e }); }
}

rpc.exports = {
  start: function () { install(); return true; },
  dump: function () { return REQS; }
};

send({ type: 'cs_http', status: 'loaded' });
