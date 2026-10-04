"""_sub_core_fetch.py — download + extract the public adjust_signature_sdk v5.0.0 cores.

Downloads (github.com/adjust/adjust_signature_sdk, tag v5.0.0, verified 2026-10-01):
  adjust-android-signature-5.0.0.aar                 2201424 B  sha256 29f3dc05...
  AdjustSigSdk-iOS-tvOS-Dynamic-5.0.0.xcframework.zip 4049357 B  sha256 0075b150...
  AdjustSigSdk-iOS-Static-5.0.0.a.zip                 902298 B  sha256 f0e67178...

Extracts into core_bins/extracted/:
  android/  libsigner.so (arm64-v8a et al), classes.jar
  ios/      ios-arm64 (device) + ios-arm64_x86_64-simulator slices of the
            dynamic xcframework, and the static libAdjustSigSdk.a
Also verifies the AAR's libsigner.so against the locally reversed reference
sha256 55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc.
"""
import hashlib
import io
import os
import sys
import zipfile

BASE = r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/core_bins"
OUT = os.path.join(BASE, "extracted")
REF_SO_SHA = "55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc"

ASSETS = {
    "adjust-android-signature-5.0.0.aar":
        "https://github.com/adjust/adjust_signature_sdk/releases/download/v5.0.0/adjust-android-signature-5.0.0.aar",
    "AdjustSigSdk-iOS-tvOS-Dynamic-5.0.0.xcframework.zip":
        "https://github.com/adjust/adjust_signature_sdk/releases/download/v5.0.0/AdjustSigSdk-iOS-tvOS-Dynamic-5.0.0.xcframework.zip",
    "AdjustSigSdk-iOS-Static-5.0.0.a.zip":
        "https://github.com/adjust/adjust_signature_sdk/releases/download/v5.0.0/AdjustSigSdk-iOS-Static-5.0.0.a.zip",
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    os.makedirs(OUT, exist_ok=True)

    # ---- Android AAR ----
    aar_path = os.path.join(BASE, "adjust-android-signature-5.0.0.aar")
    with zipfile.ZipFile(aar_path) as z:
        names = z.namelist()
        print("[AAR] entries:", len(names))
        for n in sorted(names):
            print("   ", n)
        z.extractall(os.path.join(OUT, "aar"))
        # classes.jar out separately for readability
        if "classes.jar" in names:
            data = z.read("classes.jar")
            cj = os.path.join(OUT, "aar_classes.jar")
            with open(cj, "wb") as f:
                f.write(data)
            print(f"[AAR] classes.jar -> {cj} ({len(data)} B, sha256 {sha(data)[:16]}..)")

    # find arm64 .so inside extracted AAR and verify against reference
    aar_root = os.path.join(OUT, "aar")
    found_so = {}
    for root, _dirs, files in os.walk(aar_root):
        for f in files:
            if f.endswith(".so"):
                p = os.path.join(root, f)
                with open(p, "rb") as fh:
                    data = fh.read()
                rel = os.path.relpath(p, aar_root)
                found_so[rel] = sha(data)
                print(f"[AAR] {rel}  {len(data)} B  sha256 {sha(data)[:16]}..")
                if "arm64-v8a" in rel and f == "libsigner.so":
                    match = (sha(data) == REF_SO_SHA)
                    print(f"[AAR] arm64 libsigner.so MATCHES local reversed reference: {match}")
                    if not match:
                        print("      !! different build from the reversed lib — flag in report")

    # ---- iOS dynamic xcframework ----
    xcf_path = os.path.join(BASE, "AdjustSigSdk-iOS-tvOS-Dynamic-5.0.0.xcframework.zip")
    with zipfile.ZipFile(xcf_path) as z:
        print("[XCF-dyn] entries:")
        for n in z.namelist():
            print("   ", n)
        z.extractall(os.path.join(OUT, "xcframework_dyn"))

    # ---- iOS static .a zip ----
    st_path = os.path.join(BASE, "AdjustSigSdk-iOS-Static-5.0.0.a.zip")
    with zipfile.ZipFile(st_path) as z:
        print("[XCF/static .a] entries:")
        for n in z.namelist():
            print("   ", n)
        z.extractall(os.path.join(OUT, "static_a"))

    # summarize binaries found
    print("\n== binaries ==")
    for root, _dirs, files in os.walk(OUT):
        for f in files:
            if f.endswith((".so", ".a")) or "AdjustSig" in f and "." not in f:
                p = os.path.join(root, f)
                with open(p, "rb") as fh:
                    d = fh.read(4)
                if d[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\x7fELF") or f.endswith(".a"):
                    print(f"  {p}  {os.path.getsize(p)} B  magic={d[:4].hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
