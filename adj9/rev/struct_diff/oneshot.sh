P=$(pidof com.penti.app)
echo "PID0=$P"
if [ -z "$P" ]; then
  am start -n com.penti.app/.ui.main.MainActivity >/dev/null 2>&1
  sleep 6
  P=$(pidof com.penti.app)
  echo "PID1=$P"
fi
[ -z "$P" ] && { echo "NO PROCESS"; exit 1; }
sleep 4
P=$(pidof com.penti.app)
echo "PID2=$P"
[ -z "$P" ] && { echo "DIED EARLY"; exit 1; }
/debug_ramdisk/su -c "cat /proc/$P/maps" > /data/local/tmp/sd3/maps_$P.txt
echo "MAPS DONE"
mkdir -p /data/local/tmp/sd3
for line in $(grep -E "rw-p" /data/local/tmp/sd3/maps_$P.txt | grep -v "/" | awk '{print $1}' | sed 's/-/ /'); do
  set -- $line
  lo=$((0x$1)); hi=$((0x$2)); sz=$((hi-lo))
  [ $sz -gt 268435456 ] && continue
  K=$((lo/4096)); NB=$(( (sz+4095)/4096 ))
  /debug_ramdisk/su -c "dd if=/proc/$P/mem bs=4096 skip=$K count=$NB of=/data/local/tmp/sd3/r${K}.bin" >/dev/null 2>&1
done
echo "DUMP DONE"
/debug_ramdisk/su -c "ls /data/local/tmp/sd3 | wc -l"
echo "PID_END=$(pidof com.penti.app)"
