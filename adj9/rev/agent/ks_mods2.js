'use strict';
/* ks_mods2.js - lean: list modules, then exports only for crypto-ish libs. */
function go() {
  var mods;
  try { mods = Process.enumerateModules(); } catch (e) {
    send({ t: 'err', msg: 'enumerateModules: ' + e }); return;
  }
  send({ t: 'mods', n: mods.length,
         list: mods.map(function (m) { return m.name + ' @' + m.base; }) });
  mods.forEach(function (m) {
    var nm = m.name.toLowerCase();
    if (nm.indexOf('crypto') < 0 && nm.indexOf('key') < 0 && nm.indexOf('km') < 0
        && nm.indexOf('ssl') < 0) return;
    try {
      var ex = m.enumerateExports();
      var hits = ex.filter(function (e) {
        var n = e.name;
        return n.indexOf('gcm') >= 0 || n.indexOf('GCM') >= 0 ||
               n.indexOf('HMAC') >= 0 || n.indexOf('hmac') >= 0 ||
               n.indexOf('Decrypt') >= 0 || n.indexOf('decrypt') >= 0 ||
               n.indexOf('Encrypt') >= 0 || n.indexOf('keymaster') >= 0 ||
               n.indexOf('keymint') >= 0;
      }).map(function (e) { return m.name + '!' + e.name + '@' + e.address; });
      send({ t: 'crypto', mod: m.name, n: hits.length, list: hits.slice(0, 60) });
    } catch (e) { send({ t: 'err', msg: m.name + ': ' + e }); }
  });
  send({ t: 'ready' });
}
setTimeout(go, 50);