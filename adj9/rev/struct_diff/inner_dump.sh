#!/system/bin/sh
P="$1"
mkdir -p /data/local/tmp/sd4
grep "rw-p" /proc/$P/maps | grep -v "/" | while read line; do
  range=${line%% *}
  lo=0x${range%%-*}; hi=0x${range##*-}
  sz=$((hi-lo))
  [ $sz -gt 268435456 ] && continue
  K=$((lo/4096)); NB=$(( (sz+4095)/4096 ))
  dd if=/proc/$P/mem bs=4096 skip=$K count=$NB of=/data/local/tmp/sd4/r${K}.bin 2>/dev/null
done
echo "INNER_DONE $(ls /data/local/tmp/sd4 | wc -l)"
cp /proc/$P/maps /data/local/tmp/sd4/maps_$P.txt
