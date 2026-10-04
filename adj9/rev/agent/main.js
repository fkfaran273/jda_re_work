import Java from 'frida-java-bridge';

var CAPTURED = { canonical: null, lastHeader: null, lastBlobLen: 0, errors: [],
                 raceHold: false, raceSent: false, ovr: null };


/* ---- Phase 0: swallow the guard's poisoned SIGSEGV (from stealth.js) ---- */
Process.setExceptionHandler(function (details) {
  var astr = details.address ? details.address.toString() : '0x0';
  var a = parseInt(astr, 16);
  var poisoned = astr.indexOf('0x600') === 0 && !isNaN(a) &&
                 a >= 0x600000000000 && a <= 0x700000000000;
  if (!poisoned) return false;
  send({ type: 'exception', note: 'EXC ' + details.type + ' addr=' + astr });
  try { details.context.pc = details.context.lr; } catch (e) { }
  return true;
});

/* ---- Phase 2: native self-kill blocked (from stealth.js) ---- */
try {
  function findExp(mod, name) {
    try { return Module.getGlobalExportByName(name); } catch (e) { }
    try { return Process.getModuleByName(mod).findExportByName(name); } catch (e) { }
    try { return Module.findExportByName(mod, name); } catch (e) { }
    return null;
  }
  var pthreadExit = findExp('libc.so', 'pthread_exit');
  var exitPtr = findExp('libc.so', 'exit');
  var killPtr = findExp('libc.so', 'kill');
  var tgkillPtr = findExp('libc.so', 'tgkill');
  if (exitPtr) {
    Interceptor.replace(exitPtr, new NativeCallback(function (code) {
      send({ type: 'block', note: 'libc.exit(' + code + ')' });
      if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
    }, 'void', ['int']));
  }
  if (killPtr) {
    var origKill = new NativeFunction(killPtr, 'int', ['int', 'int']);
    Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
      if (pid === Process.id) { send({ type: 'block', note: 'kill(self,' + sig + ')' }); return 0; }
      return origKill(pid, sig);
    }, 'int', ['int', 'int']));
  }
  if (tgkillPtr) {
    var origTg = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
    Interceptor.replace(tgkillPtr, new NativeCallback(function (tgid, tid, sig) {
      if (tgid === Process.id && (sig === 9 || sig === 6)) {
        send({ type: 'block', note: 'tgkill(self,' + tid + ',' + sig + ')' });
        return 0;
      }
      return origTg(tgid, tid, sig);
    }, 'int', ['int', 'int', 'int']));
  }
  send({ type: 'log', note: 'phase2 ok exit=' + !!exitPtr + ' kill=' + !!killPtr + ' tgkill=' + !!tgkillPtr });
} catch (e) { send({ type: 'log', note: 'phase2 err: ' + e }); }

function b64(bytes) {
  try { return Java.use('android.util.Base64').encodeToString(bytes, 2); }
  catch (e) { return null; }
}

function install() {
  Java.perform(function () {
    var HashMap = Java.use('java.util.HashMap');
    var Base64 = Java.use('android.util.Base64');

    // ---- anti-kill: neutralize every self-termination path ----
    try {
      var Sys = Java.use('java.lang.System');
      Sys.exit.implementation = function (c) {
        send({ type: 'blocked', what: 'System.exit(' + c + ')' });
      };
    } catch (e) { }
    try {
      var Rt = Java.use('java.lang.Runtime');
      Rt.exit.implementation = function (c) { send({ type: 'blocked', what: 'Runtime.exit' }); };
      Rt.halt.implementation = function (c) { send({ type: 'blocked', what: 'Runtime.halt' }); };
    } catch (e) { }
    try {
      var Proc = Java.use('android.os.Process');
      Proc.killProcess.implementation = function (pid) {
        send({ type: 'blocked', what: 'Process.killProcess(' + pid + ')' });
      };
    } catch (e) { }
    try {
      var Thr = Java.use('java.lang.Thread');
      Thr.getDefaultUncaughtExceptionHandler.overload = Thr.getDefaultUncaughtExceptionHandler;
    } catch (e) { }
    send({ type: 'killguard', on: true });

    // capture: d3.a(String) -> UTF-8 bytes  (kp.js-proven pattern)
    try {
      var d3o = Java.use('com.adjust.sdk.sig.d3').a.overload('java.lang.String');
      d3o.implementation = function (s) {
        var r = d3o.call(this, s);
        try { send({ type: 'd3', sig: 'String', inStr: ('' + s), outLen: r ? r.length : 0 }); } catch (e) {}
        return r;
      };
    } catch (e) { CAPTURED.errors.push('d3.a: ' + e); }

    // capture: t1.a(Context, byte[]) -> H  (the HMAC boundary)
    try {
      var T1c = Java.use('com.adjust.sdk.sig.t1');
      var B64u = Java.use('android.util.Base64');
      var t1o = T1c.a.overload('android.content.Context', '[B');
      t1o.implementation = function (ctx, msg) {
        CAPTURED.lastT1 = this;
        var r = t1o.call(this, ctx, msg);
        try {
          send({ type: 'hmac', sig: 'Ctx[B',
                 inB64: msg ? B64u.encodeToString(msg, 2) : null,
                 outB64: r ? B64u.encodeToString(r, 2) : null });
        } catch (e) {}
        return r;
      };
    } catch (e) { CAPTURED.errors.push('t1.a: ' + e); }

    // capture: NLH.a(ctx, map, hmac, sdk) -> 192B blob
    try {
      var NLHc = Java.use('com.adjust.sdk.sig.NativeLibHelper');
      var B64n = Java.use('android.util.Base64');
      var nOv = null;
      NLHc.a.overloads.forEach(function (o) {
        if (o.argumentTypes.length === 4) nOv = o;
      });
      if (nOv) {
        nOv.implementation = function (ctx, map, hmac, sdk) {
          var r = nOv.call(this, ctx, map, hmac, sdk);
          try {
            CAPTURED.lastBlob = r ? B64n.encodeToString(r, 2) : null;
            var prs = [];
            var ks = map.keySet().iterator();
            while (ks.hasNext()) {
              var k = '' + ks.next();
              var v = map.get(k);
              prs.push([k, (v === null || v === undefined) ? null : ('' + v)]);
            }
            send({ type: 'nSign', outLen: r ? r.length : 0,
                   b64: CAPTURED.lastBlob,
                   argH: (hmac && hmac.length) ? B64n.encodeToString(hmac, 2) : null });
            send({ type: 'sigpairs', pairs: prs, blobLen: r ? r.length : 0 });
          } catch (e) {}
          // ---- verbatim race: if armed, PARK the app's send thread here the
          // first time it signs its OWN attribution map, after the blob exists
          // but before sign() returns (=> before its HTTP send). The PC relays
          // the verbatim blob first, then un-parks us.
          if (CAPTURED.raceHold) {
            var isAtt = false;
            try { isAtt = ('' + map.get('activity_kind')) === 'attribution'; } catch (e2) {}
            if (isAtt && !CAPTURED.raceSent) {
              CAPTURED.raceSent = true;
              send({ type: 'race_hold', blobB64: CAPTURED.lastBlob,
                     pairs: prs || [] });
              var Th = Java.use('java.lang.Thread');
              var t0r = Date.now();
              while (Date.now() - t0r < 12000) { Th.sleep(50); }
            }
          }
          return r;
        };
      }
    } catch (e) { CAPTURED.errors.push('NLH.a: ' + e); }

    // (u2.a hook REMOVED — 2-arg overload selector threw under frida 17 and the
    //  header is computed offline in Python from the blob; sigpairs come from
    //  Signer.sign's sigmap instead.)

    // capture: the REAL act/glob maps the SDK passes to Signer.sign
    try {
      var SignerCls = Java.use('com.adjust.sdk.sig.Signer');
      SignerCls.sign.overload('android.content.Context', 'java.util.Map',
        'java.util.Map', 'java.util.Map').implementation = function (ctx, act, glob, res) {
        function mapToObj(m) {
          var o = {};
          try {
            var it = m.keySet().iterator();
            while (it.hasNext()) {
              var k = Java.cast(it.next(), Java.use('java.lang.String')).toString();
              var v = m.get(k);
              o[k] = (v === null || v === undefined) ? null :
                Java.cast(v, Java.use('java.lang.String')).toString();
            }
          } catch (e) { }
          return o;
        }
        CAPTURED.lastSigMap = { activity: mapToObj(act), globals: mapToObj(glob) };
        send({ type: 'sigmap', activity: CAPTURED.lastSigMap.activity,
               globals: CAPTURED.lastSigMap.globals });
        // ---- piggyback mint: re-sign the SAME real maps with fresh stamps +
        //      attribution kind, on the SAME live signer (keystore H + native
        //      body). In-process, synchronous, indistinguishable from the
        //      session+click back-to-back bursts the app itself does.
        try {
          if (!(CAPTURED.mintCount >= 10) && !CAPTURED.minting) {
            CAPTURED.minting = true;
            // E1: fire TWO mints BACK-TO-BACK inside this same hook, cloning the
            // live maps via putAll each time (the path proven working in
            // minted4). Same stamps both times -> any blob difference is a
            // random/counter input (#0/#2/#8 candidate).
            var StC = Java.use('java.lang.String');
            var LHm = Java.use('java.util.LinkedHashMap');
            if (!CAPTURED.stamp1) {
              var d = new Date(Date.now() - 1000 + 5.5 * 3600 * 1000);
              function p2(n) { return ('0' + n).slice(-2); }
              function p3(n) { return ('00' + n).slice(-3); }
              CAPTURED.stamp1 = d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' +
                p2(d.getUTCDate()) + 'T' + p2(d.getUTCHours()) + ':' +
                p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds()) + '.' +
                p3(d.getUTCMilliseconds()) + 'Z+0530';
            }
            function orderedPairs(m) {
              var arr = [];
              var it = m.keySet().iterator();
              while (it.hasNext()) {
                var k = '' + it.next();
                var v = m.get(k);
                arr.push([k, (v === null || v === undefined) ? null : '' + v]);
              }
              return arr;
            }
            // E2: busy-wait to just after a second rollover so BOTH mints sign
            // within the SAME wall-clock second (the header law's second input).
            // If the two blobs are then byte-identical, the pipeline is fully
            // deterministic given (map, second, H, key2) -> pure Python signer.
            var spinStart = Date.now();
            while (Date.now() % 1000 > 80) { }
            send({ type: 'log', note: 'E2 aligned at ' + (Date.now() % 1000) +
                   'ms into the second (spun ' + (Date.now() - spinStart) + 'ms)' });
            for (var mi = 1; mi <= 10; mi++) {
              var stamp = CAPTURED.stamp1;
              try {
                var OVR = CAPTURED.ovr || {};
                var act2, glob2;
                if (OVR.replace) {
                  // EXACT-MAP MINT: sign only the pairs we pass (so the signed
                  // claim set equals the claim set the server derives from the
                  // request we will send).
                  act2 = LHm.$new();
                  Object.keys(OVR.activity || {}).forEach(function (k) {
                    act2.put(StC.$new(k), StC.$new('' + OVR.activity[k]));
                  });
                  glob2 = LHm.$new();
                  Object.keys(OVR.globals || {}).forEach(function (k) {
                    glob2.put(StC.$new(k), StC.$new('' + OVR.globals[k]));
                  });
                } else {
                  act2 = LHm.$new(); act2.putAll(act);
                  glob2 = LHm.$new(); glob2.putAll(glob);
                }
                act2.put(StC.$new('created_at'), StC.$new(stamp));
                act2.put(StC.$new('sent_at'), StC.$new(stamp));
                act2.put(StC.$new('activity_kind'),
                         StC.$new(OVR.kind || 'attribution'));
                // keep BOTH maps on the same kind: a stale 'session' in the
                // globals map is what silently made the minted payload the
                // wrong activity_kind (and broke recognition).
                glob2.put(StC.$new('activity_kind'),
                          StC.$new(OVR.kind || 'attribution'));
                if (!OVR.replace && OVR.activity) {
                  Object.keys(OVR.activity).forEach(function (k) {
                    act2.put(StC.$new(k), StC.$new('' + OVR.activity[k]));
                  });
                }
                if (!OVR.replace && OVR.globals) {
                  Object.keys(OVR.globals).forEach(function (k) {
                    glob2.put(StC.$new(k), StC.$new('' + OVR.globals[k]));
                  });
                }
                var res2 = LHm.$new();
                var pb = null, errN = null;
                try { pb = this.sign(ctx, act2, glob2, res2); }
                catch (eS2) { errN = '' + eS2; }
                var out = { ok: false, error: errN,
                            canonical: CAPTURED.canonical,
                            blobLen: CAPTURED.lastBlobLen,
                            blobB64: CAPTURED.lastBlob, stamp: stamp,
                            auth: null, mapPairs: [], resPairs: [] };
                if (pb !== null && pb !== undefined && pb.length === 192) out.ok = true;
                try { out.mapPairs = orderedPairs(act2).concat(orderedPairs(glob2)); } catch (eO) { }
                try { out.resPairs = orderedPairs(res2); } catch (eO2) { }
                for (var ri = 0; ri < out.resPairs.length; ri++) {
                  if (out.resPairs[ri][0] === 'authorization') out.auth = out.resPairs[ri][1];
                }
                CAPTURED.mintCount = mi;
                send({ type: 'piggy', result: out });
                try {
                  var fp = ctx.getExternalFilesDir(null).getAbsolutePath() +
                    '/mint_out' + mi + '.json';
                  var fos = Java.use('java.io.FileOutputStream').$new(fp);
                  fos.write(StC.$new(JSON.stringify(out)).getBytes('UTF-8'));
                  fos.close();
                } catch (eF) { send({ type: 'log', note: 'piggy file err: ' + eF }); }
              } catch (eM2) { send({ type: 'log', note: 'piggy ' + mi + ' err: ' + eM2 }); }
            }
            CAPTURED.minting = false;
          }
        } catch (eM) { CAPTURED.minting = false; send({ type: 'log', note: 'piggy err: ' + eM }); }
        return this.sign(ctx, act, glob, res);
      };
    } catch (e) { CAPTURED.errors.push('Signer.sign: ' + e); }

    rpc.exports = {
      setmint: function (o) { CAPTURED.ovr = o; return true; },
      health: function () {
        try {
          var Signer = Java.use('com.adjust.sdk.sig.Signer');
          return { loaded: true, hasOnResume: (typeof Signer.onResume === 'function') };
        } catch (e) { return { loaded: false, error: String(e) }; }
      },

      mint3: function (obj) {
        var out = { ok: false, error: null };
        try {
          var LH = Java.use('java.util.LinkedHashMap');
          var Str = Java.use('java.lang.String');
          var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          var NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
          var B64 = Java.use('android.util.Base64');
          CAPTURED.canonical = obj.canonical;
          // map in EXACT canonical order for nSign
          var map = LH.$new();
          obj.pairs.forEach(function (kv) {
            map.put(Str.$new(kv[0]), kv[1] === null ? null : Str.$new(kv[1]));
          });
          // H: real keystore instance if we caught one signing; else random —
          // server cannot verify H provenance, only #4/body consistency.
          var H = null, hsrc = 'random';
          var t1i = CAPTURED.lastT1;
          if (t1i !== null && t1i !== undefined) {
            try {
              H = t1i.a(ctx, Str.$new(obj.canonical).getBytes('UTF-8'));
              hsrc = 'keystore';
            } catch (eH) { H = null; }
          }
          if (H === null || H === undefined) {
            var arr = [];
            for (var i = 0; i < 32; i++) arr.push(((Math.random() * 256) | 0) - 128);
            H = Java.array('byte', arr);
          }
          var t0 = Math.floor(Date.now() / 1000);
          var nlh;
          try { nlh = NLH.$new(); } catch (eN) { nlh = null; }
          if (nlh === null) {
            var fN = null;
            Java.choose('com.adjust.sdk.sig.NativeLibHelper',
                        { onMatch: function (i) { fN = i; }, onComplete: function () { } });
            if (fN === null) { throw new Error('NLH: no ctor and no live instance'); }
            nlh = fN;
          }
          var blob = nlh.a(ctx, map, H, 31);
          out.ok = blob !== null && blob !== undefined && blob.length === 192;
          out.hsrc = hsrc;
          out.mintEpoch = t0;
          out.H = (H === null) ? null : B64.encodeToString(H, 2);
          out.blobLen = blob === null ? 0 : blob.length;
          out.blobB64 = blob === null ? null : B64.encodeToString(blob, 2);
          // EMIT + PERSIST BEFORE ANY RETURN PATH — the RPC channel has died
          // on us before (script destroyed right after nSign).
          try { send({ type: 'mint_result', result: out }); } catch (eS) { }
          try {
            var fp = ctx.getExternalFilesDir(null).getAbsolutePath() + '/mint_out.json';
            var fos = Java.use('java.io.FileOutputStream').$new(fp);
            fos.write(Str.$new(JSON.stringify(out)).getBytes('UTF-8'));
            fos.close();
          } catch (eF) { try { send({ type: 'mint_file_err', err: '' + eF }); } catch (e2) { } }
        } catch (e) {
          out.error = (e && e.message) ? e.message : String(e);
          try { send({ type: 'mint_result', result: out }); } catch (eS2) { }
        }
        return out;
      },
      mint2: function (obj) {
        var out = { ok: false, error: null };
        try {
          var base = CAPTURED.lastSigMap;
          if (!base) { out.error = 'no real sigmap captured yet'; return out; }
          var act = HashMap.$new(), glob = HashMap.$new();
          Object.keys(base.activity).forEach(function (k) {
            act.put(k, base.activity[k] === null ? null : String(base.activity[k]));
          });
          Object.keys(base.globals).forEach(function (k) {
            glob.put(k, base.globals[k] === null ? null : String(base.globals[k]));
          });
          // overrides: identity + timestamps + activity kind
          Object.keys(obj.activity || {}).forEach(function (k) {
            act.put(k, String(obj.activity[k]));
          });
          Object.keys(obj.globals || {}).forEach(function (k) {
            glob.put(k, String(obj.globals[k]));
          });
          var Signer = Java.use('com.adjust.sdk.sig.Signer');
          var signer = Signer.$new();
          try { signer.onResume(); } catch (e) { }
          var res = HashMap.$new();
          var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          CAPTURED.canonical = null; CAPTURED.lastHeader = null; CAPTURED.lastBlobLen = 0;
          signer.sign.overload('android.content.Context', 'java.util.Map',
            'java.util.Map', 'java.util.Map').call(signer, ctx, act, glob, res);
          var auth = res.get('authorization');
          out.ok = auth !== null && auth !== undefined;
          out.authorization = out.ok ? Java.cast(auth, Java.use('java.lang.String')).toString() : null;
          out.canonical = CAPTURED.canonical;
          out.blobLen = CAPTURED.lastBlobLen;
          out.resKeys = []; out.resVals = [];
          var it = res.keySet().iterator();
          while (it.hasNext()) {
            var k = Java.cast(it.next(), Java.use('java.lang.String')).toString();
            var v = res.get(k);
            out.resKeys.push(k);
            out.resVals.push(v === null ? null : Java.cast(v, Java.use('java.lang.String')).toString());
          }
        } catch (e) {
          out.error = (e && e.message) ? e.message : String(e);
        }
        /* persist immediately: script may be destroyed before the next RPC */
        try {
          CAPTURED.mints = CAPTURED.mints || [];
          CAPTURED.mints.push(out);
          var fp = Java.use('java.io.File');
          var dir = ctx.getExternalFilesDir(null).getAbsolutePath();
          var path = dir + '/mint_log.json';
          var fos = Java.use('java.io.FileOutputStream').$new(path, true); /* append */
          fos.write(StC.$new(JSON.stringify(out) + '\n').getBytes('UTF-8'));
          fos.close();
        } catch (eF) { out.fileErr = '' + eF; }
        return out;
      },

      lastcapture: function () { return CAPTURED; },

      readfile: function (p) {
        /* read an app-private file from inside the process (no root needed) */
        var out = { path: p, ok: false, list: null, dataB64: null, error: null };
        try {
          var Fc = Java.use('java.io.File');
          var base = ctx.getExternalFilesDir(null).getParentFile();
          var f = Fc.$new(base, p);
          if (f.isDirectory && f.isDirectory()) {
            var names = f.list();
            out.list = [];
            for (var i = 0; i < names.length; i++) out.list.push(names[i]);
            out.ok = true;
            return out;
          }
          var fis = Java.use('java.io.FileInputStream').$new(f);
          var baos = Java.use('java.io.ByteArrayOutputStream').$new();
          var buf = Java.array('byte', new Array(8192).fill(0));
          var n;
          while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
          fis.close();
          var B64 = Java.use('android.util.Base64');
          out.dataB64 = B64.encodeToString(baos.toByteArray(), 2);
          out.ok = true;
        } catch (e) { out.error = '' + e; }
        return out;
      },

      race: function (on) {
        CAPTURED.raceHold = !!on;
        if (!on) { CAPTURED.raceSent = false; }
        return { raceHold: CAPTURED.raceHold, raceSent: CAPTURED.raceSent };
      }
    };

    send({ type: 'ready', errors: CAPTURED.errors });
  });
}

// Java bridge may need the VM to appear; retry briefly
var tries = 0;
function boot() {
  try { install(); } catch (e) {
    if (++tries < 40) setTimeout(boot, 250);
    else send({ type: 'ready', errors: ['java never ready: ' + e] });
  }
}
// frida-java-bridge exposes available(); guard on it when present
if (Java.available !== false) setTimeout(boot, 200);
else send({ type: 'ready', errors: ['java unavailable'] });



