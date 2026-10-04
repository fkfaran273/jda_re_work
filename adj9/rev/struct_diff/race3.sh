#!/system/bin/sh
am start -n com.penti.app/.ui.main.MainActivity >/dev/null 2>&1
i=0; MAIN=""
while [ $i -lt 60 ]; do
  for p in $(pidof com.penti.app); do
    c=$(cat /proc/$p/cmdline 2>/dev/null | tr -d '\0')
    if [ "$c" = "com.penti.app" ]; then MAIN=$p; break; fi
  done
  [ -n "$MAIN" ] && break
  sleep 0.1; i=$((i+1))
done
echo "MAIN=$MAIN"
[ -z "$MAIN" ] && exit 1
sleep 2
rm -rf /data/local/tmp/sdR; mkdir -p /data/local/tmp/sdR
grep "rw-p" /proc/$MAIN/maps | grep -E "scudo|libc_malloc" | grep -v "/" > /data/local/tmp/rr.txt
hexdec() { echo "$1" | awk '{ v=0; n=length($0); for(i=1;i<=n;i++){ c=substr($0,i,1); v=v*16+index("0123456789abcdef",c)-1 } printf "%d", v }'; }
n=0
while read -r line; do
  range=${line%% *}
  lo=$(hexdec ${range%%-*}); hi=$(hexdec ${range##*-})
  set -- $(awk -v lo=$lo -v hi=$hi 'BEGIN{printf "%d %d", int(lo/4096), int((hi-lo+4095)/4096)}')
  K=$1; NB=$2
  dd if=/proc/$MAIN/mem bs=4096 skip=$K count=$NB of=/data/local/tmp/sdR/r${K}.bin 2>/dev/null
  n=$((n+1))
done < /data/local/tmp/rr.txt
echo "RACE_DUMPED n=$n pid=$MAIN"
cp /proc/$MAIN/maps /data/local/tmp/sdR/maps_$MAIN.txt 2>/dev/null
echo "ALIVE=$(pidof com.penti.app)"
