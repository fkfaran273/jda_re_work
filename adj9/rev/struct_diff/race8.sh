#!/system/bin/sh
W="$1"; TAG="$2"; WAIT="${3:-75}"
[ "$W" = "1" ] && { rm -f /data/data/com.penti.app/files/AdjustIoActivityState; echo "WIPED"; }
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
input keyevent 3
echo "HOMED at startup"
sleep "$WAIT"
AL=0
for p in $(pidof com.penti.app); do [ "$p" = "$MAIN" ] && AL=1; done
echo "ALIVE=$AL pid=$MAIN after ${WAIT}s"
[ "$AL" = "0" ] && exit 1
ls -la /data/data/com.penti.app/files/AdjustIoActivityState 2>/dev/null || echo "STATE_FILE_ABSENT"
rm -rf /data/local/tmp/sd$TAG; mkdir -p /data/local/tmp/sd$TAG
grep "rw-p" /proc/$MAIN/maps | grep -v "/" | awk -v m=268435456 '
function hex2dec(s,  v,i,c,n) { v=0; n=length(s); for(i=1;i<=n;i++){c=substr(s,i,1); v=v*16+index("0123456789abcdef",c)-1} return v }
{
  split($1, a, "-"); lo=hex2dec(a[1]); hi=hex2dec(a[2]);
  if (hi-lo > m) next;
  K=int(lo/4096); NB=int((hi-lo+4095)/4096);
  print K" "NB;
}' > /data/local/tmp/kk_$TAG.txt
T=$(wc -l < /data/local/tmp/kk_$TAG.txt)
Q=$((T/4+1))
split -l $Q /data/local/tmp/kk_$TAG.txt /data/local/tmp/kk_$TAG_
dumpfile() {
awk -v P="$1" '{ printf "dd if=/proc/%s/mem bs=4096 skip=%s count=%s of=/data/local/tmp/sd%s/r%s.bin 2>/dev/null\n", P, $1, $2, "'"$3"'", $1 }' "$2" | sh
}
for f in /data/local/tmp/kk_$TAG_*; do dumpfile "$MAIN" "$f" "$TAG" & done
wait
cp /proc/$MAIN/maps /data/local/tmp/sd$TAG/maps_$MAIN.txt 2>/dev/null && echo "MAPS_OK" || echo "MAPS_FAIL"
cp /data/local/tmp/kk_$TAG.txt /data/local/tmp/sd$TAG/kk.txt
chmod -R 755 /data/local/tmp/sd$TAG
echo "DUMP_DONE files=$(ls /data/local/tmp/sd$TAG | wc -l) pid=$MAIN"
echo "FINAL=$(pidof com.penti.app)"
