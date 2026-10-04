/* randcap_src.js - capture the native rand()/srand() traffic during REAL signings.
 *
 * Phase 1 (passive): intercept native rand()+srand()+time() PLT entries inside
 * the app process and log every call with a stack tag (nsign vs seedfn vs other).
 * Phase 2 (on demand, rpc): report the log slices around each signing.
 */
'use strict';

var SEED_FN_LO = 0x129000, SEED_FN_HI = 0x12d000;
var NSIGN_LO = 0xda980, NSIGN_HI = 0xdbf00;

var randLog = [];
var srandLog = [];
var armed = true;

function tag(addr) {
  if (addr >= NSIGN_LO && addr <= NSIGN_HI) return 'nsign';
  if (addr >= SEED_FN_LO && addr <= SEED_FN_HI) return 'seedfn';
  return 'other';
}

function hookNative() {
  var mods = Process.enumerateModules();
  var base = null;
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].path.indexOf('libsigner.so') >= 0) { base = mods[i].base; break; }
  }
  if (!base) { send({ type: 'randcap', status: 'no-libsigner' }); return false; }
  var randAddr = base.add(0x148d10);
  var srandAddr = base.add(0x148d30);
  var timeAddr = base.add(0x148d20);
  try {
    Interceptor.attach(randAddr, {
      onEnter: function (args) {
        this.ret = DebugSymbol.fromAddress(this.returnAddress);
      },
      onLeave: function (retval) {
        if (!armed) return;
        var ra = this.ret ? this.ret.address : ptr(0);
        var raN = parseInt(ra.toString(), 16);
        randLog.push({ v: retval.toInt32() >>> 0, ra: raN, tag: tag(raN) });
        if (randLog.length > 4000) randLog.splice(0, 1000);
      }
    });
    Interceptor.attach(srandAddr, {
      onEnter: function (args) {
        if (!armed) return;
        var ra = DebugSymbol.fromAddress(this.returnAddress);
        var raS = ra ? ra.toString() : '';
        var raN = ra ? parseInt(ra.address.toString(), 16) : 0;
        srandLog.push({ seed: args[0].toInt32() >>> 0, ra: raN, tag: tag(raN), sym: raS.slice(0, 80) });
        if (srandLog.length > 400) srandLog.splice(0, 100);
      }
    });
    Interceptor.attach(timeAddr, {
      onEnter: function (args) { this.tptr = args[0]; },
      onLeave: function (retval) {
        if (!armed) return;
        var ra = DebugSymbol.fromAddress(this.returnAddress);
        var raN = ra ? parseInt(ra.address.toString(), 16) : 0;
        if (raN >= SEED_FN_LO && raN <= SEED_FN_HI) {
          srandLog.push({ time_ret: retval.toInt32() >>> 0, ra: raN, tag: 'seedfn-time' });
        }
      }
    });
  } catch (e) {
    send({ type: 'randcap', status: 'hook-err', err: '' + e });
    return false;
  }
  send({ type: 'randcap', status: 'hooked', libsigner: base.toString() });
  return true;
}

var done = false;
var savedArgs = null;

rpc.exports = {
  status: function () {
    return { rand: randLog.length, srand: srandLog.length, saved: !!savedArgs };
  },
  getlog: function () {
    return { rand: randLog.slice(-400), srand: srandLog.slice(-40) };
  },
  clear: function () { randLog = []; srandLog = []; return { ok: true }; }
};

import Java from 'frida-java-bridge';
Java.perform(function () {
  if (!hookNative()) return;
  try {
    var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
    var ov = null;
    NLH.a.overloads.forEach(function (o) {
      if (o.argumentTypes.length === 4) ov = o;
    });
    if (!ov) { send({ type: 'randcap', status: 'no-4arg' }); return; }
    ov.implementation = function (ctx, map, hmac, sdk) {
      var base = this.a(ctx, map, hmac, sdk);
      if (!done) {
        done = true;
        savedArgs = { ctx: ctx, map: map, hmac: hmac, sdk: sdk };
        send({ type: 'randcap', status: 'captured-first-sign' });
      }
      return base;
    };
    send({ type: 'randcap', status: 'java-hooked' });
  } catch (e) { send({ type: 'randcap', status: 'java-err', err: '' + e }); }
});
