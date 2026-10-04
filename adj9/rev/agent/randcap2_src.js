/* randcap2_src.js - capture rand()/srand() traffic via GOT-patch logging.
 *
 * Direct Interceptor.attach on the PLT stub fails on this device
 * ("unable to intercept function at ...5d10"). Instead we resolve the REAL
 * libc rand/srand/time addresses via DebugSymbol, then patch the app's
 * libsigner.so GOT slots? No - simpler and safer: hook the REAL libc
 * functions (they are normal code, interceptable) and filter by caller:
 * only record calls whose return address lies inside libsigner.so's
 * .text range (passed in from Python after reading the maps).
 */
'use strict';

var SIGN_LO = 0, SIGN_HI = 0;
var randLog = [];
var srandLog = [];
var armed = true;

function inSigner(addrN) { return addrN >= SIGN_LO && addrN <= SIGN_HI; }

rpc.exports = {
  status: function () {
    return { rand: randLog.length, srand: srandLog.length };
  },
  getlog: function () {
    return { rand: randLog.slice(-600), srand: srandLog.slice(-60) };
  },
  clear: function () { randLog = []; srandLog = []; return { ok: true }; },
  setrange: function (lo, hi) { SIGN_LO = lo; SIGN_HI = hi; return { ok: true, lo: lo, hi: hi }; }
};

function hookReal(name, isSrand) {
  var addr = null;
  try {
    var sym = DebugSymbol.fromName('rand');
  } catch (e) { }
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
  if (!addr) { send({ type: 'randcap2', status: 'no-' + name, err: 'not found' }); return; }
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
    send({ type: 'randcap2', status: 'hooked-' + name, addr: addr.toString() });
  } catch (e) {
    send({ type: 'randcap2', status: 'hook-err-' + name, err: '' + e });
  }
}

hookReal('rand', false);
hookReal('srand', true);
