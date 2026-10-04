tries=0
P=""
while [ $tries -lt 6 ]; do
  tries=$((tries+1))
  am start -n com.penti.app/.ui.main.MainActivity >/dev/null 2>&1
  sleep 5
  P=$(pidof com.penti.app)
  [ -z "$P" ] && continue
  sleep 6
  P2=$(pidof com.penti.app)
  [ "$P" != "$P2" ] || [ -z "$P2" ] && continue
  echo "STABLE P=$P2 tries=$tries"
  break
done
if [ -z "$P2" ] || [ "$P" != "$P2" ]; then echo "FAILED after $tries"; exit 1; fi
/debug_ramdisk/su -c "cat /proc/$P2/maps" > /data/local/tmp/maps_$P2.txt
echo "MAPS DONE"
mkdir -p /data/local/tmp/sd3
n=0
for line in $(grep -E "rw-p" /data/local/tmp/maps_$P2.txt | grep -v "/" | awk '{print $1}' | sed 's/-/ /'); do
  set -- $line
  lo=$((0x$1)); hi=$((0x$2)); sz=$((hi-lo))
  [ $sz -gt 268435456 ] && continue
  K=$((lo/4096)); NB=$(( (sz+4095)/4096 ))
  /debug_ramdisk/su -c "dd if=/proc/$P2/mem bs=4096 skip=$K count=$NB of=/data/local/tmp/sd3/r${K}.bin" >/dev/null 2>&1
  n=$((n+1))
done
echo "DUMP DONE n=$n"
echo "PID_END=$(pidof com.penti.app)"
