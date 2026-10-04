#!/system/bin/sh
attempt=1
MAIN=""
while [ $attempt -le 4 ]; do
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
  echo "attempt=$attempt MAIN=$MAIN"
  [ -z "$MAIN" ] && { attempt=$((attempt+1)); continue; }
  input keyevent 3
  sleep 4
  OK=0
  for p in $(pidof com.penti.app); do [ "$p" = "$MAIN" ] && OK=1; done
  if [ "$OK" = "1" ]; then echo "STABLE $MAIN"; break; fi
  echo "died attempt=$attempt"
  MAIN=""
  attempt=$((attempt+1))
done
[ -z "$MAIN" ] && { echo "ALL_ATTEMPTS_FAILED"; exit 1; }
rm -rf /data/local/tmp/sdF; mkdir -p /data/local/tmp/sdF
grep "rw-p" /proc/$MAIN/maps | grep -v "/" | awk -v m=268435456 '
function hex2dec(s,  v,i,c,n) { v=0; n=length(s); for(i=1;i<=n;i++){c=substr(s,i,1); v=v*16+index("0123456789abcdef",c)-1} return v }
{
  split($1, a, "-"); lo=hex2dec(a[1]); hi=hex2dec(a[2]);
  if (hi-lo > m) next;
  K=int(lo/4096); NB=int((hi-lo+4095)/4096);
  print K" "NB;
}' > /data/local/tmp/kk.txt
T=$(wc -l < /data/local/tmp/kk.txt)
echo "RANGES=$T"
Q=$((T/4+1))
split -l $Q /data/local/tmp/kk.txt /data/local/tmp/kk_
dumpfile() {
awk -v P="$1" '
{ printf "dd if=/proc/%s/mem bs=4096 skip=%s count=%s of=/data/local/tmp/sdF/r%s.bin 2>/dev/null\n", P, $1, $2, $1 }
' "$2" | sh
}
for f in /data/local/tmp/kk_*; do dumpfile "$MAIN" "$f" & done
wait
echo "DUMP_DONE pid=$MAIN"
cp /proc/$MAIN/maps /data/local/tmp/sdF/maps_$MAIN.txt 2>/dev/null && echo "MAPS_OK" || echo "MAPS_FAIL"
cp /data/local/tmp/kk.txt /data/local/tmp/sdF/kk.txt
chmod -R 755 /data/local/tmp/sdF
ls /data/local/tmp/sdF | wc -l
echo "ALIVE=$(pidof com.penti.app)"
