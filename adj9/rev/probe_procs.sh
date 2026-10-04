#!/system/bin/sh
for pid in 623 666 11561 1244 11567; do
  echo "--- pid $pid : $(tr "\000" " " < /proc/$pid/cmdline 2>/dev/null)"
  grep -m1 -oE "lib(puresoftkeymasterdevice|keymaster[a-z_]*|keymint[a-z_]*|km_compat_service|soft_attestation_cert|tricky_store|libcrypto)\.so" /proc/$pid/maps 2>/dev/null | sort -u
done
