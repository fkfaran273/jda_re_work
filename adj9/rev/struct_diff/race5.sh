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
sleep 1.5
rm -rf /data/local/tmp/sdR; mkdir -p /data/local/tmp/sdR
grep "rw-p" /proc/$MAIN/maps | grep -E "scudo|libc_malloc" | grep -v "/" > /data/local/tmp/rr.txt
T=$(wc -l < /data/local/tmp/rr.txt)
H=$((T/2+1))
head -n $H /data/local/tmp/rr.txt > /data/local/tmp/rr1.txt
tail -n +$((H+1)) /data/local/tmp/rr.txt > /data/local/tmp/rr2.txt
gen() {
awk -v P="$1" '
function hex2dec(s,  v,i,c,n) { v=0; n=length(s); for(i=1;i<=n;i++){c=substr(s,i,1); v=v*16+index("0123456789abcdef",c)-1} return v }
{
  split($1, a, "-"); lo=hex2dec(a[1]); hi=hex2dec(a[2]);
  K=int(lo/4096); NB=int((hi-lo+4095)/4096);
  printf "dd if=/proc/%s/mem bs=4096 skip=%d count=%d of=/data/local/tmp/sdR/r%d.bin 2>/dev/null\n", P, K, NB, K;
}' "$2" | sh
}
gen "$MAIN" /data/local/tmp/rr1.txt &
gen "$MAIN" /data/local/tmp/rr2.txt &
wait
echo "RACE5_DONE pid=$MAIN"
cp /proc/$MAIN/maps /data/local/tmp/sdR/maps_$MAIN.txt 2>/dev/null || echo "MAPS_FAIL(dead)"
cp /data/local/tmp/rr.txt /data/local/tmp/sdR/rr.txt
chmod -R 755 /data/local/tmp/sdR
ls /data/local/tmp/sdR | wc -l
