import Java from 'frida-java-bridge';
'use strict';

// ---- state shared across rpc calls -----------------------------------------
var STATE = {
  loader: null,          // Java.ClassFactory that can resolve Signer
  signerClass: null,
  lastAct: null,         // the app's REAL activity map (captured from a live sign)
  lastGlob: null,        // the app's REAL globals map
  loaderErr: null
};

function findSignerFactory() {
  if (STATE.loader) { return STATE.loader; }
  // The Adjust SDK lives in com.penti.app's own classloader, not the default one
  // Java.use picks (which is often GMS). Enumerate loaders and take the first
  // that can resolve the Signer class.
  var loaders = [];
  try {
    Java.enumerateClassLoaders({
      onMatch: function (loader) { loaders.push(loader); },
      onComplete: function () {}
    });
  } catch (e) { STATE.loaderErr = 'enum loaders: ' + e; return null; }
  var errs = [];
  for (var i = 0; i < loaders.length; i++) {
    try {
      var factory = Java.ClassFactory.get(loaders[i]);
      factory.use('com.adjust.sdk.sig.Signer');
      STATE.loader = factory;
      STATE.signerClass = 'com.adjust.sdk.sig.Signer';
      return factory;
    } catch (e) { errs.push('' + e); }
  }
  STATE.loaderErr = 'no classloader loaded Signer (' + loaders.length + ' loaders tried): ' + (errs[0] || '?');
  return null;
}

function readStaticBool(factory, clsName, fieldName) {
  try {
    var cls = factory.use(clsName).class;
    var f = cls.getDeclaredField(fieldName);
    f.setAccessible(true);
    if (f.getType().getName() === 'boolean') { return f.getBoolean(null); }
    var v = f.get(null);
    return (v !== null && v !== undefined) ? !!v.booleanValue() : null;
  } catch (e) { return null; }
}

function javaTypeList(arr) {
  var out = [];
  try { for (var i = 0; i < arr.length; i++) { out.push(arr[i].getName()); } }
  catch (e) { out.push('?'); }
  return out.join(',');
}

function mapToObj(m) {
  if (m === null || m === undefined) { return null; }
  var o = {};
  try {
    var it = m.keySet().iterator();
    while (it.hasNext()) {
      var k = '' + it.next();
      var v = m.get(k);
      o[k] = (v === null || v === undefined) ? null : '' + v;
    }
  } catch (e) { o.__err = '' + e; }
  return o;
}

// Install capture hooks on the Signer so we can observe the app's OWN signing
// and grab its live (fully-initialized) Signer instance.
function installCapture(factory) {
  var String = Java.use('java.lang.String');
  try {
    var Signer = factory.use('com.adjust.sdk.sig.Signer');
    var orig = Signer.sign.overload(
      'android.content.Context', 'java.util.Map', 'java.util.Map', 'java.util.Map');
    orig.implementation = function (ctx, act, glob, res) {
      // Optionally inject a synthetic activity map BEFORE the app signs, so the
      // app's own (fully-initialized) singleton signs our params.
      var injected = false;
      if (STATE.inject) {
        try {
          act.clear();
          var keys = Object.keys(STATE.inject);
          for (var q = 0; q < keys.length; q++) { act.put(keys[q], '' + STATE.inject[keys[q]]); }
          injected = true;
        } catch (e) { STATE.injectErr = '' + e; }
      }
      STATE.lastAct = mapToObj(act);
      STATE.lastGlob = mapToObj(glob);
      STATE.appSigner = this;
      var rv = orig.call(this, ctx, act, glob, res);
      // did the app's real sign produce an authorization?
      var auth = null;
      try { var a = res.get('authorization'); if (a !== null) auth = '' + a; } catch (e) {}
      STATE.lastAuth = auth;
      send({ type: 'app-sign', act: STATE.lastAct, glob: STATE.lastGlob,
             injected: injected, auth: auth });
      return rv;
    };
  } catch (e) { STATE.captureErr = 'hook Signer.sign: ' + e; }
}

rpc.exports = {
  // synchronous readiness probe
  health: function () {
    var h = { loaderFound: false, err: STATE.loaderErr, captureErr: STATE.captureErr };
    Java.performNow(function () {
      var f = findSignerFactory();
      if (f) { h.loaderFound = true; installCapture(f); }
    });
    h.loaderFound = !!STATE.loader;
    h.lastActKeys = STATE.lastAct ? Object.keys(STATE.lastAct) : null;
    return h;
  },

  // Walk the init chain and report guard Signer.c after each step, to find what
  // flips it true (the app sets it during its own startup; a fresh instance
  // does not). Also returns whether the app's live Signer is available.
  kick: function () {
    var out = { steps: [] };
    Java.performNow(function () {
      try {
        var factory = findSignerFactory();
        if (!factory) { out.error = STATE.loaderErr; return; }
        var Thread = Java.use('java.lang.Thread');
        var Signer = factory.use('com.adjust.sdk.sig.Signer');
        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        function cval() { return readStaticBool(factory, 'com.adjust.sdk.sig.Signer', 'c'); }
        function step(name, fn) {
          var r = null, e = null;
          try { r = fn(); } catch (ex) { e = '' + (ex.message || ex); }
          out.steps.push({ name: name, err: e, c: cval() });
        }
        out.steps.push({ name: 'initial', c: cval(), haveAppSigner: !!STATE.appSigner });
        var signer = STATE.appSigner || Signer.$new();
        step('onResume', function () { signer.onResume(); return null; });
        Thread.sleep(300); out.steps.push({ name: 'after300ms', c: cval() });
        // NativeLibHelper field a  (cast to its class so methods are callable)
        try {
          var NLH = factory.use('com.adjust.sdk.sig.NativeLibHelper');
          var fA = Signer.class.getDeclaredField('a'); fA.setAccessible(true);
          var nlh = Java.cast(fA.get(signer), NLH);
          out.haveNlh = nlh !== null;
          if (nlh) {
            step('nlh.nOnResume', function () { nlh.nOnResume(); return null; });
            Thread.sleep(400); out.steps.push({ name: 'nlh_after400ms', c: cval() });
            step('nlh.a()', function () { return '' + nlh.a(); });
            Thread.sleep(200); out.steps.push({ name: 'nlh_a_after200ms', c: cval() });
          }
        } catch (e) { out.nlhErr = '' + e; }
        // t1 field b
        try {
          var T1 = factory.use('com.adjust.sdk.sig.t1');
          var fB = Signer.class.getDeclaredField('b'); fB.setAccessible(true);
          var t1 = Java.cast(fB.get(signer), T1);
          out.haveT1 = t1 !== null;
          if (t1) { step('t1.b(ctx)', function () { t1.b(ctx); return null; }); }
        } catch (e) { out.t1Err = '' + e; }
        Thread.sleep(400); out.steps.push({ name: 'final', c: cval() });
        out.ok = true;
      } catch (e) { out.error = '' + e; }
    });
    return out;
  },
  // classname e.g. 'com.adjust.sdk.sig.Signer' or '...sig.t2'
  introspect: function (classname) {
    var res = { ok: false, classname: classname };
    Java.performNow(function () {
      try {
        var factory = findSignerFactory();
        if (!factory) { res.error = STATE.loaderErr; return; }
        var cls = factory.use(classname);
        var meths = cls.class.getDeclaredMethods();
        var mlist = [];
        for (var i = 0; i < meths.length; i++) {
          var m = meths[i];
          mlist.push('' + m.getName() + '(' + javaTypeList(m.getParameterTypes()) + ')');
        }
        var fields = cls.class.getDeclaredFields();
        var flist = [];
        for (var j = 0; j < fields.length; j++) {
          var f = fields[j];
          f.setAccessible(true);
          var fdesc = '' + f.getName() + ' : ' + f.getType().getName();
          try {
            var Modifier = Java.use('java.lang.reflect.Modifier');
            if (Modifier.isStatic(f.getModifiers())) {
              fdesc += '  = ' + ('' + f.get(null));
            }
          } catch (e2) { fdesc += '  (static val err)'; }
          flist.push(fdesc);
        }
        res.methods = mlist; res.fields = flist; res.ok = true;
      } catch (e) { res.error = '' + e; }
    });
    return res;
  },

  // Arm map injection: the next natural app sign will sign THIS activity map.
  setInject: function (map) { STATE.inject = map; return { armed: !!map }; },

  // Result of the last natural app sign (did it emit an authorization?).
  lastResult: function () {
    return { act: STATE.lastAct, glob: STATE.lastGlob, auth: STATE.lastAuth,
             haveSigner: !!STATE.appSigner, injectErr: STATE.injectErr };
  },

  // Capture the app's real activity/globals map on its next natural sign.
  lastCapture: function () {
    return { act: STATE.lastAct, glob: STATE.lastGlob, haveSigner: !!STATE.appSigner };
  },

  // Block (on our RPC thread) until the app's live Signer has signed at least
  // once, giving us its initialized instance. The app signs on its own thread,
  // so sleeping here does not block it.
  awaitAppSigner: function (ms) {
    var deadline = Date.now() + (ms || 1500);
    while (!STATE.appSigner && Date.now() < deadline) {
      Java.performNow(function () {
        var Thread = Java.use('java.lang.Thread');
        Thread.sleep(50);
      });
    }
    return { haveSigner: !!STATE.appSigner, act: STATE.lastAct };
  },

  // Mint a signature using the REAL device signer. Uses performNow so the
  // result is filled in before we return (perform() is async -> empty result).
  mint: function (obj) {
    var out = { ok: false, error: null };
    Java.performNow(function () {
      try {
        var factory = findSignerFactory();
        if (!factory) { out.error = STATE.loaderErr; return; }

        var String = Java.use('java.lang.String');
        var HashMap = Java.use('java.util.HashMap');
        var Base64 = Java.use('android.util.Base64');

        var Signer = factory.use('com.adjust.sdk.sig.Signer');
        var signer = STATE.appSigner;   // app's live, fully-initialized instance
        if (!signer) {
          signer = Signer.$new();
          try { signer.onResume(); } catch (e) {}
        }
        out.usedAppSigner = !!STATE.appSigner;

        // onResume() loads the native lib ASYNChronously and sets static guard
        // Signer.c = true when ready. sign() silently no-ops until then, so poll.
        var Thread = Java.use('java.lang.Thread');
        var deadline = Date.now() + 3500;
        var guard = readStaticBool(factory, 'com.adjust.sdk.sig.Signer', 'c');
        while (!guard && Date.now() < deadline) {
          Thread.sleep(25);
          guard = readStaticBool(factory, 'com.adjust.sdk.sig.Signer', 'c');
        }
        out.guardC = guard;

        var act = HashMap.$new();
        Object.keys(obj.activity).forEach(function (k) { act.put(k, String.valueOf(obj.activity[k])); });
        var glob = HashMap.$new();
        Object.keys(obj.globals).forEach(function (k) { glob.put(k, String.valueOf(obj.globals[k])); });
        var res = HashMap.$new();

        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

        // capture the blob nSign produces + the canonical string (d3.a)
        var capturedBlob = null;
        try {
          var NLH = factory.use('com.adjust.sdk.sig.NativeLibHelper');
          var nlg = NLH.a.overload('android.content.Context', 'java.util.LinkedHashMap', '[B', 'int');
          var nlgOrig = nlg.implementation;
          nlg.implementation = function (c, map, hmac, sdk) {
            var r = nlgOrig.call(this, c, map, hmac, sdk);
            if (r !== null) { capturedBlob = Base64.encodeToString(r, 2); }
            return r;
          };
        } catch (e) { out.nlmErr = '' + e; }

        var capturedCanon = null;
        try {
          var d3 = factory.use('com.adjust.sdk.sig.d3');
          var d3g = d3.a.overload('java.lang.String');
          var d3Orig = d3g.implementation;
          d3g.implementation = function (s) {
            var str = Java.cast(s, String).toString();
            capturedCanon = str;
            return d3Orig.call(this, s);
          };
        } catch (e) { out.d3Err = '' + e; }

        out.stage = 'about-to-sign';
        signer.sign.overload('android.content.Context', 'java.util.Map', 'java.util.Map', 'java.util.Map')
          .call(signer, ctx, act, glob, res);
        out.stage = 'signed';

        var auth = res.get('authorization');
        out.ok = auth !== null && auth !== undefined;
        out.authorization = out.ok ? Java.cast(auth, String).toString() : null;
        out.nSignBlob = capturedBlob;
        out.canonicalLen = capturedCanon ? capturedCanon.length : 0;
        out.canonical = capturedCanon;
        out.resKeys = Object.keys(mapToObj(res) || {});
      } catch (e) {
        out.stage = 'threw';
        out.error = '' + e;
        out.eClass = (e && e.$className) ? e.$className : null;
        out.eMsg = (e && e.message) ? e.message : null;
        out.stack = (e && e.stack) ? ('' + e.stack) : null;
        try { out.resKeys = Object.keys(mapToObj(res) || {}); } catch (_) {}
      }
    });
    return out;
  }
};
