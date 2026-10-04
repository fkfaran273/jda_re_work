/* creditsea_descs.js — frida: capture the genuine 5.8.0 descriptor plane.
 *
 * Hook NativeLibHelper.a(Context, LinkedHashMap, byte[], int) (the wrapper).
 * Inside the hook, build DYNAMIC scan patterns from the live map:
 *   - values-only claims prefix (read-order law: sorted keys with
 *     activity_kind/client_sdk last) -> 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI79457bcc'
 *   - k=v claims prefix            -> 'adj_verification=KlcAG2cb'
 *   - k\x01v claims prefix         -> 'adj_verification\x01KlcAG2cb'
 *   - k: prefix / pinned variants
 * plus the STATIC markers:
 *   - 06f5ffce... (creditsea cert SHA-1 = D9 data)
 *   - bffffffffffffd1f0007... (D8 as captured on penti - verify identical)
 *   - the arg3 digest bytes (finds the VM input plane)
 *   - the arg3 digest bytes AGAIN but scanned AFTER return (output plane)
 * Dump memory around every hit. Everything goes to the PC as hex.
 */
'use strict';

import Java from 'frida-java-bridge';

function hexlify(buf) {
    var u = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
    return s;
}

function strToHex(s) {
    var out = '';
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c > 0xFF) return null;           // non-latin1 -> not a byte marker
        out += ('0' + c.toString(16)).slice(-2);
    }
    return out;
}

function scanAll(pattern, tag, cap) {
    var out = [];
    if (!pattern) return out;
    var ranges = Process.enumerateRanges({ protection: 'r--', coalesce: false })
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: false }));
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (r.size > 0x10000000) continue;               // skip >256MB ranges
        try {
            var matches = Memory.scanSync(r.base, r.size, pattern);
            for (var j = 0; j < matches.length; j++) {
                out.push({ tag: tag, addr: matches[j].address.toString(),
                           range: r.base.toString() + '+' + r.size });
                if (out.length >= cap) return out;
            }
        } catch (e) { /* unreadable range */ }
    }
    return out;
}

function dumpAround(addrStr, before, total, tag) {
    try {
        var a = ptr(addrStr);
        var data = a.sub(before).readByteArray(total);
        send({ type: 'dump', tag: tag, addr: addrStr, hex: hexlify(data) });
    } catch (e) {
        send({ type: 'dump_err', tag: tag, addr: addrStr, err: '' + e });
    }
}

// Read the live LinkedHashMap into a JS {key: value} object.
function readMap(m) {
    var o = {};
    var it = m.keySet().iterator();
    while (it.hasNext()) {
        var k = it.next();
        var v = m.get(k);
        o[k] = (v === null) ? 'null' : ('' + v);
    }
    return o;
}

// The read-order law seen in the LSPosed mapget trace:
// sorted(all keys present) with activity_kind+client_sdk moved to the end.
function readOrderKeys(keys) {
    var sorted = keys.slice().sort();
    var front = sorted.filter(function (k) {
        return k !== 'activity_kind' && k !== 'client_sdk';
    });
    ['activity_kind', 'client_sdk'].forEach(function (k) {
        if (sorted.indexOf(k) >= 0) front.push(k);
    });
    return front;
}

Java.perform(function () {
    send({ type: 'status', msg: 'java perform, hooking wrapper' });
    var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
    NLH.a.overload('android.content.Context', 'java.util.LinkedHashMap',
                   '[B', 'int').implementation = function (ctx, map, digest, level) {
        var digHex = digest ? hexlify(digest) : null;
        send({ type: 'wrapper_call', level: level,
               digest: digHex,
               mapsize: map ? map.size() : -1 });

        // ---- build dynamic markers from the live map ----
        var claims = {};
        try {
            claims = readMap(map);
            var keys = Object.keys(claims);
            var ro = readOrderKeys(keys);
            // candidate claims byte streams (prefixes, 24 B is unique enough)
            var cands = {};
            var c1 = ro.map(function (k) { return claims[k]; }).join('');
            cands['vals_readorder'] = c1.slice(0, 40);
            var c2 = ro.map(function (k) { return k + '=' + claims[k]; }).join('');
            cands['kv_eq'] = c2.slice(0, 40);
            var c3 = ro.map(function (k) { return k + '\x01' + claims[k]; }).join('\x02');
            cands['kv_1_2'] = c3.slice(0, 40);
            var c4 = ro.map(function (k) { return k + claims[k]; }).join('');
            cands['kv_concat'] = c4.slice(0, 40);
            // read-order map_order style but with map insertion order too
            var c5 = keys.map(function (k) { return claims[k]; }).join('');
            cands['vals_maporder'] = c5.slice(0, 40);
            // twice variant of the read-order values
            cands['vals_readorder_x2'] = (c1 + c1).slice(0, 48);
            var markers = [];
            for (var name in cands) {
                var hx = strToHex(cands[name]);
                if (hx && hx.length >= 24) markers.push({ tag: 'claims_' + name, hex: hx, text: cands[name] });
            }
            send({ type: 'claims_markers', markers: markers,
                   read_order: ro, map_size: keys.length });
            // ---- scan for the dynamic claims markers (BEFORE the call) ----
            for (var i = 0; i < markers.length; i++) {
                var hits = scanAll(markers[i].hex, markers[i].tag, 6);
                if (hits.length) {
                    send({ type: 'hits', tag: markers[i].tag, hits: hits });
                    for (var j = 0; j < hits.length && j < 3; j++) {
                        dumpAround(hits[j].addr, 0x100, 0x800, markers[i].tag + '#' + j);
                    }
                } else {
                    send({ type: 'no_hit', tag: markers[i].tag });
                }
            }
        } catch (e) {
            send({ type: 'claims_err', err: '' + e, stack: e.stack });
        }

        // ---- scan for the digest bytes (arg3) before the call ----
        if (digHex && digHex.length >= 24) {
            var dhits = scanAll(digHex.slice(0, 32), 'digest_in', 8);
            send({ type: 'hits', tag: 'digest_in', hits: dhits });
            for (var d = 0; d < dhits.length && d < 4; d++) {
                dumpAround(dhits[d].addr, 0x100, 0x600, 'digest_in#' + d);
            }
        }
        // static D8 + cert markers
        var stat = scanAll('bffffffffffffd1f0007000000000000', 'd8_penti', 8);
        send({ type: 'hits', tag: 'd8_penti', hits: stat });
        for (var s = 0; s < stat.length && s < 4; s++) {
            dumpAround(stat[s].addr, 0x80, 0x200, 'd8#' + s);
        }

        var t0 = Date.now();
        var r = this.a(ctx, map, digest, level);
        send({ type: 'wrapper_out', ms: Date.now() - t0,
               hex: r ? hexlify(r) : null, len: r ? r.length : 0 });

        // ---- after the call: rescan digest + claims markers ----
        try {
            if (digHex) {
                var dh2 = scanAll(digHex.slice(0, 32), 'digest_out', 8);
                send({ type: 'hits', tag: 'digest_out', hits: dh2 });
            }
            if (typeof c1 === 'string' && c1.length >= 20) {
                var ch2 = scanAll(strToHex(c1.slice(0, 20)), 'claims_after', 6);
                send({ type: 'hits', tag: 'claims_after', hits: ch2 });
                for (var c = 0; c < ch2.length && c < 3; c++) {
                    dumpAround(ch2[c].addr, 0x100, 0x800, 'claims_after#' + c);
                }
            }
        } catch (e) {
            send({ type: 'scan_err', err: '' + e, stack: e.stack });
        }
        send({ type: 'scan_done' });
        return r;
    };
    send({ type: 'status', msg: 'wrapper hooked, waiting for signing' });
});
