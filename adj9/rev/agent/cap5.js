/* cap5.js — aged-attach + Java fireEvent trigger + full descriptor dump.
   Compiled with frida-compile (Java comes from frida-java-bridge). */
import Java from 'frida-java-bridge';

'use strict';
var ev = { sign: [], srand: [], ready: null, err: [], fired: null };

Process.setExceptionHandler(function (details) {
  var astr = details.address ? details.address.toString() : '0x0';
  var a = parseInt(astr, 16);
  if (astr.indexOf('0x600') === 0 && !isNaN(a) &&
      a >= 0x600000000000 && a <= 0x700000000000) {
    try { details.context.pc = details.context.lr; } catch (e) {}
    return true;
  }
  return false;
});

function rd(ab) {
  var u = new Uint8Array(ab), s = '';
  for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return s;
}

function hookLib(base) {
  send({ type: 'lib', base: base.toString() });
  try {
    Interceptor.attach(base.add(0x148d30), { onEnter: function (a) {
      ev.srand.push({ seed: a[0].toInt32() >>> 0, t: Date.now() });
    }});
  } catch (e) { ev.err.push('srand: ' + e); }
  try {
    var nemit = 0, cur = null;
    Interceptor.attach(base.add(0x146ed8), { onEnter: function (a) {
      nemit++;
      if (cur && nemit <= 8000)
        cur.emit.push({ q: a[1].toString(), n: a[2].toInt32(), v: a[3].toInt32() >>> 0 });
    }});
    Interceptor.attach(base.add(0x100094), {
      onEnter: function (a) {
        cur = { t: Date.now(), count: a[2].toInt32(), descs: [], emit: [] };
        try {
          var p = a[1];
          for (var i = 0; i < Math.min(cur.count, 12) && !p.isNull(); i++) {
            var d = {};
            try {
              d.w0 = p.readU32();
              var np = p.add(8).readPointer();
              d.next = np.toString();
              if (!np.isNull()) {
                var want = d.w0 >>> 2;
                if (want <= 0 || want > 2048) want = 1024;
                try { d.payload = rd(np.readByteArray(want * 4)); }
                catch (e4) { d.payloadErr = '' + e4; }
              }
            } catch (e3) { d.err = '' + e3; }
            cur.descs.push(d);
            p = p.add(8).readPointer();
          }
        } catch (e2) { cur.dumpErr = '' + e2; }
        ev.sign.push(cur);
        send({ type: 'sign', idx: ev.sign.length - 1, count: cur.count,
               heads: cur.descs.map(function (d) { return d.w0; }) });
      },
      onLeave: function (r) {
        if (cur) { cur.ret = r.toInt32(); cur = null;
          send({ type: 'signDone', idx: ev.sign.length - 1 }); }
      }
    });
  } catch (e) { ev.err.push('vm: ' + e); }
  ev.ready = true;
  send({ type: 'ready' });
}

var t0 = Date.now();
var iv = setInterval(function () {
  if (Date.now() - t0 > 120000) { clearInterval(iv); send({ type: 'timeout' }); return; }
  var m = null;
  try { m = Process.findModuleByName('libsigner.so'); } catch (e) {}
  if (m) { clearInterval(iv); hookLib(m.base); }
}, 50);

Java.perform(function () {
  try {
    var Sys = Java.use('java.lang.System');
    Sys.exit.implementation = function (code) {
      send({ type: 'blocked', what: 'System.exit(' + code + ')' });
    };
  } catch (e) { ev.err.push('guard: ' + e); }
});

rpc.exports = {
  fire: function (token) {
    try {
      var r = null;
      Java.perform(function () {
        var Adjust = Java.use('com.adjust.sdk.Adjust');
        var AdjustEvent = Java.use('com.adjust.sdk.AdjustEvent');
        var e2 = AdjustEvent.$new(token || 'bfi71x');
        Adjust.trackEvent(e2);
        r = 'fired';
      });
      ev.fired = Date.now();
      return r;
    } catch (e) { ev.err.push('fire: ' + e); return 'ERR ' + e; }
  },
  events: function () { return JSON.stringify(ev); },
  save: function () {
    var out = JSON.stringify(ev);
    var f = new File('/data/data/com.penti.app/files/adj9_cap5.json', 'w');
    f.write(out); f.flush(); f.close();
    return out.length;
  }
};
