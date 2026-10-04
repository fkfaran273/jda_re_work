/* randcap3_src.js - self-ranging version. Resolves libsigner.so base + .text size
 * from inside the process (no adb maps scraping, no stale pid), hooks the REAL
 * libc rand/srand, filters by caller inside libsigner .text.
 */
'use strict';

var SIGN_LO = 0, SIGN_HI = 0;
var randLog = [];
var srandLog = [];
var armed = true;

(function initRange() {
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].path.indexOf('libsigner.so') >= 0) {
      SIGN_LO = mods[i].base.toInt32() >>> 0;
      SIGN_HI = (mods[i].base.add(mods[i].size).toInt32() >>> 0);
      break;
    }
  }
})();

function inSigner(addrN) { return addrN >= SIGN_LO && addrN <= SIGN_HI; }

rpc.exports = {
  status: function () {
    return { rand: randLog.length, srand: srandLog.length,
             lo: SIGN_LO.toString(16), hi: SIGN_HI.toString(16) };
  },
  getlog: function () {
    return { rand: randLog.slice(-600), srand: srandLog.slice(-60) };
  },
  clear: function () { randLog = []; srandLog = []; return { ok: true }; }
};

function hookReal(name, isSrand) {
  var addr = null;
  var m = Process.enumerateModules();
  for (var i = 0; i < m.length; i++) {
    if (m[i].path.indexOf('libc.so') >= 0 || m[i].path.indexOf('libc.') >= 0) {
      try {
        var exps = m[i].enumerateExports();
        for (var j = 0; j < exps.length; j++) {
          if (exps[j].name === name) { addr = exps[j].address; break; }
        }
      } catch (e) { }
      if (addr) break;
    }
  }
  if (!addr) { send({ type: 'randcap3', status: 'no-' + name }); return; }
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        if (!armed) return;
        this.seed = isSrand ? args[0].toInt32() >>> 0 : 0;
        try {
          var ra = DebugSymbol.fromAddress(this.returnAddress);
          this.raN = ra ? parseInt(ra.address.toString(), 16) : 0;
        } catch (e) { this.raN = 0; }
      },
      onLeave: function (retval) {
        if (!armed) return;
        if (!inSigner(this.raN)) return;
        if (isSrand) {
          srandLog.push({ seed: this.seed, ra: this.raN });
          if (srandLog.length > 400) srandLog.splice(0, 100);
        } else {
          randLog.push({ v: retval.toInt32() >>> 0, ra: this.raN });
          if (randLog.length > 6000) randLog.splice(0, 1000);
        }
      }
    });
    send({ type: 'randcap3', status: 'hooked-' + name, addr: addr.toString() });
  } catch (e) {
    send({ type: 'randcap3', status: 'hook-err-' + name, err: '' + e });
  }
}

send({ type: 'randcap3', status: 'range',
       lo: SIGN_LO.toString(16), hi: SIGN_HI.toString(16) });
hookReal('rand', false);
hookReal('srand', true);
