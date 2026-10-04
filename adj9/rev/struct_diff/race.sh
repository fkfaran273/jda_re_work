#!/system/bin/sh
P=$(pidof com.penti.app)
am start -n com.penti.app/.ui.main.MainActivity >/dev/null 2>&1
sleep 3.5
P=$(pidof com.penti.app)
echo "RACE_PID=$P"
[ -z "$P" ] && exit 1
rm -rf /data/local/tmp/sdC; mkdir -p /data/local/tmp/sdC
grep "rw-p" /proc/$P/maps | grep -E "scudo|libc_malloc" | while read line; do
  range=${line%% *}
  lo=$((0x${range%%-*})); hi=$((0x${range##*-}))
  K=$((lo/4096)); NB=$(((hi-lo+4095)/4096))
  dd if=/proc/$P/mem bs=4096 skip=$K count=$NB of=/data/local/tmp/sdC/r${K}.bin 2>/dev/null
done
echo "SCUDO_DUMPED $(ls /data/local/tmp/sdC | wc -l)"
echo "PID_NOW=$(pidof com.penti.app)"
cp /proc/$P/maps /data/local/tmp/sdC/maps.txt 2>/dev/null
