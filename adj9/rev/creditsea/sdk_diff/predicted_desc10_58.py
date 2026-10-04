# predicted_desc10_58.py - desc10 builder for creditsea's Adjust SDK 5.8.0.
#
# VERDICT FROM THE 5.7.0-vs-5.8.0 DEX DIFF (adj9/rev/creditsea/sdk_diff/FINDINGS.md):
#   The claims key set and order are UNCHANGED in 5.8.0. The whole
#   com/adjust/sdk/sig package (incl. the u2 claims assembler and
#   NativeLibHelper.nSign(Context, LinkedHashMap, byte[], int)) is
#   instruction-identical to 5.7.0 after register normalization, and
#   PackageBuilder's parameter key set has NO additions or removals
#   (the only new strings are 4 *conditional* ff_* flags that require the app
#   to call the new disable*Reading() APIs - creditsea does not).
#
# Therefore build_desc10 for 5.8.0 is the proven 5.7.0 law re-exported.
# Same interface as desc10_law.build_desc10 so the law tests run against it:
#   from predicted_desc10_58 import build_desc10, desc10_keys
#
# CAVEATS (see FINDINGS.md):
#   * client_sdk VALUE differs by version: 'android5.7.0' -> 'android5.8.0'
#     (it is a claims VALUE taken from the request, so callers supplying the
#     request's own values are unaffected).
#   * If a 5.8.0 request ever carries one of the conditional keys
#     ff_gps_adid_disabled / ff_android_id_disabled / ff_fire_adid_disabled /
#     ff_plugins_device_ids_disabled, this law does NOT cover it (none
#     observed; they do not exist in 5.7.0 captures).
#   * D8 (descriptor #8) and the claims law are NOT the unverifiable-signature
#     cause; descriptor #9 = APK cert SHA-1 differs per app:
#     penti  fad0f10d60f93c17937b2f1eb6c09691ae7d74bd
#     creditsea 06f5ffcee0541608765407ab9e0180e7b1b7e7d0
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
# ^ sdk_diff/ -> creditsea/ -> rev/ ; desc10_law.py lives in rev/
import desc10_law  # noqa: E402  (the proven 5.7.0 law, slice 96)

# Re-export the identical key sets and emission order.
PROFILE_COMMON = desc10_law.PROFILE_COMMON
OPTIONAL_PROFILE = desc10_law.OPTIONAL_PROFILE
SESSION_PROFILE = desc10_law.SESSION_PROFILE
CLICK_PROFILE = desc10_law.CLICK_PROFILE
SESSION_TAIL = desc10_law.SESSION_TAIL
CLICK_TAIL = desc10_law.CLICK_TAIL
BLOCK2 = desc10_law.BLOCK2
PINNED = desc10_law.PINNED
ATTRIBUTION_PROFILE = desc10_law.ATTRIBUTION_PROFILE
ATTRIBUTION_TAIL = desc10_law.ATTRIBUTION_TAIL

CLIENT_SDK_58 = 'android5.8.0'  # claims VALUE for 5.8.0 (PROVEN from dex)

# Conditional 5.8.0-only ff_* keys: NOT part of this law (only injected when
# the app calls AdjustConfig.disable*Reading(); none seen in creditsea code).
FF_KEYS_58_CONDITIONAL = ['ff_gps_adid_disabled', 'ff_android_id_disabled',
                          'ff_fire_adid_disabled', 'ff_plugins_device_ids_disabled']


def desc10_keys(kind, val=None):
    """Identical emission order to the proven 5.7.0 law."""
    return desc10_law.desc10_keys(kind, val)


def pad4(b):
    return desc10_law.pad4(b)


def build_desc10(val, kind):
    """Byte-identical interface to desc10_law.build_desc10 (5.8.0: same law)."""
    return desc10_law.build_desc10(val, kind)


if __name__ == '__main__':
    # Self-check: the law self-test still passes through this re-export.
    print('desc10_keys(session) =', desc10_keys('session'))
    ok = desc10_law.self_test()
    print('desc10_law self_test through predicted_desc10_58:', 'OK' if ok else 'FAIL')
    raise SystemExit(0 if ok else 1)
