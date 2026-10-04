/* region_writer.js - hook the functions that WRITE the region source buffers.

The copy loop reads the region from heap source buffers (written at init).
The writers are the store sites inside the builder that fill them.
We hook the KNOWN copy-loop read site (0x10017c) and the store sites to see
who writes into the source buffers. Also hook the init-time store sites that
write the tile values.
*/
'use strict';

import Java from 'frida-java-bridge';

var WRITES = [];
var armed = false;
var seen = {};

function libBase() {
  var ms = Process.enumerateModules();
  for (var i = 0; i < ms.length; i++) if (ms[i].path.indexOf('libsigner.so') >= 0) return ms[i].base;
  return null;
}

function hookWriters(b) {
  // the known copy-loop read site (0x10017c reads the source array)
  // The WRITERS are the str sites that write into the source buffers.
  // From slice 140/139: the source buffers are at a known heap region.
  // We hook the STORE sites (the write side) that fill the source buffers.
  // From the disasm: the store sites are the `str x/w` after each blr in the builder.
  var sites = [
    0x9afa8, 0x9b668, 0x9bf08, 0x9bf3c, 0x9c974, 0x9cf3c, 0x9cfc8,
    0x9cfcc, 0x9d3f0, 0x9db3c,
  ];
  var names = {};
  for (var i = 0; i < sites.length; i++) {
    var va = sites[i];
    try {
      Interceptor.attach(b.add(va), {
        onEnter: function () {
          if (!armed) return;
          var c = this.context;
          var rec = { site: '0x' + this.address.toString(16),
                      x0: c.x0.toString(), x1: c.x1.toString(),
                      x8: c.x8.toString(), w8: c.w8 >>> 0,
                      x12: c.x12.toString(), w12: c.w12 >>> 0 };
          WRITES.push(rec);
        }
      });
    } catch (e) { }
  }
  send({ type: 'log', note: 'writers hooked: ' + sites.length });
}

rpc.exports = {
  start: function () {
    var b = libBase();
    if (!b) return 'no-libsigner';
    hookWriters(b);
    armed = true;
    return { ok: true, base: b.toString() };
  },
  dump: function () { return { n: WRITES.length, writes: WRITES.slice(-200) }; },
};

send({ type: 'region_writer', status: 'loaded' });
