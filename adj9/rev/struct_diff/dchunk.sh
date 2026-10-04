MAIN=$1
N=$2
LO=$(awk -v n=$N 'BEGIN{print 33554432 + n*268435456}')
HI=$(awk -v n=$N 'BEGIN{print 33554432 + (n+1)*268435456}')
K=$(awk -v lo=$LO 'BEGIN{printf "%d", int(lo/4096)}')
NB=$(awk -v d=$LO 'BEGIN{printf "%d", int(268435456/4096)}')
dd if=/proc/$MAIN/mem bs=4096 skip=$K count=$NB of=/data/local/tmp/dal$N.bin 2>/dev/null
chmod 666 /data/local/tmp/dal$N.bin; ls -l /data/local/tmp/dal$N.bin
