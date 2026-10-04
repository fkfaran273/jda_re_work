// rand-trace: log srand seed, every rand() return, and the nSign output header
// for com.penti.app. Attach AFTER app is running (device frida-server16 on 27042).
function main() {
  var libsigner = null;
  try { libsigner = Process.findModuleByName("libsigner.so"); } catch (e) {}
  if (!libsigner) { console.log("[!] libsigner.so not loaded yet"); return; }
  var base = libsigner.base;
  console.log("[*] libsigner base: " + base);

  var srand = Module.findExportByName("libsigner.so", "srand");
  var rand = Module.findExportByName("libsigner.so", "rand");
  // NB: srand/rand are libc imports; hooking by module libsigner.so resolves the
  // PLT-resolved libc symbols. Fall back to global lookup:
  if (!srand) srand = Module.findExportByName(null, "srand");
  if (!rand) rand = Module.findExportByName(null, "rand");
  console.log("[*] srand@" + srand + " rand@" + rand);

  var seq = [];          // rand returns for current window
  var lastSeed = null;
  var lastSeedMs = 0;

  Interceptor.attach(srand, {
    onEnter: function (args) {
      lastSeed = args[0].toInt32();
      lastSeedMs = Date.now();
      seq = [];
      console.log("[srand] seed=" + lastSeed + " t=" + lastSeedMs);
    }
  });

  Interceptor.attach(rand, {
    onEnter: function (args) { },
    onLeave: function (ret) {
      seq.push(ret.toInt32());
      if (seq.length <= 12) {
        console.log("[rand #" + seq.length + "] = " + ret.toInt32() +
                    " (0x" + (ret.toInt32() >>> 0).toString(16) + ")");
      } else if (seq.length === 13) {
        console.log("[rand] ... (more follow, not printed)");
      }
    }
  });

  // nSign entry to delimit the window
  var nSign = base.add(0xdb1cc);
  Interceptor.attach(nSign, {
    onEnter: function (args) {
      console.log("=== nSign enter ===");
      seq = [];
    },
    onLeave: function (retval) {
      console.log("=== nSign leave === rands=" + seq.length);
      console.log("[rands] " + JSON.stringify(seq));
    }
  });

  // catch Java-side canonical+HMAC to correlate
  try {
    var Java = Java.use("com.adjust.sdk.sig.NativeLibHelper");
  } catch (e) { }
}
main();
