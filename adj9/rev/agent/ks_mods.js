'use strict';
/* ks_mods.js - report loaded modules + crypto-ish exports in this process. */
var mods = Process.enumerateModules();
var out = [];
mods.forEach(function (m) {
  out.push(m.name + ' @' + m.base + ' size=0x' + m.size.toString(16));
});
send({ t: 'mods', n: mods.length, list: out });
var HITS = [];
mods.forEach(function (m) {
  try {
    m.enumerateExports().forEach(function (e) {
      var n = e.name;
      if (n.indexOf('gcm') >= 0 || n.indexOf('GCM') >= 0 || n.indexOf('HMAC') >= 0 ||
          n.indexOf('Hmac') >= 0 || n.indexOf('hmac') >= 0 ||
          n.indexOf('Decrypt') >= 0 || n.indexOf('keymaster') >= 0 ||
          n.indexOf('Keymaster') >= 0 || n.indexOf('km_') >= 0 ||
          n.indexOf('keymint') >= 0 || n.indexOf('KeyMint') >= 0) {
        HITS.push(m.name + '!' + n + '@' + e.address);
      }
    });
  } catch (e) { }
});
send({ t: 'crypto', n: HITS.length, list: HITS.slice(0, 120) });
send({ t: 'ready' });