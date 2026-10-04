#!/system/bin/sh
MAIN=$1
START=$2
END=$3
rm -rf /data/local/tmp/sdD16; mkdir -p /data/local/tmp/sdD16
awk -v P="$MAIN" -v s=$START -v e=$END '
BEGIN{
  n = int((e-s)/16777216);
  for(i=0;i<n;i++){
    lo = s + i*16777216;
    K = int(lo/4096);
    NB = 4096;
    printf "dd if=/proc/%s/mem bs=4096 skip=%d count=%d of=/data/local/tmp/sdD16/d16_%d.bin 2>/dev/null\n", P, K, NB, i;
  }
}' | sh
chmod -R 755 /data/local/tmp/sdD16
echo "FILES=$(ls /data/local/tmp/sdD16 | wc -l) SIZE=$(du -sk /data/local/tmp/sdD16 | cut -f1) ALIVE=$(pidof com.penti.app)"
