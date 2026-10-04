#!/system/bin/sh
# run under su; arg1 = dump dir name
D="$1"
am start -n com.penti.app/.ui.main.MainActivity >/dev/null 2>&1
i=0
MAIN=""
while [ $i -lt 40 ]; do
  for p in $(pidof com.penti.app); do
    c=$(cat /proc/$p/cmdline 2>/dev/null | tr -d '\0')
    [ "$c" = "com.penti.app" ] && MAIN=$p && break
  done
  [ -n "$MAIN" ] && break
  sleep 0.2
  i=$((i+1))
done
echo "MAIN=$MAIN t=+$((i*2/10)).$((i*2%10))s"
[ -z "$MAIN" ] && exit 1
sleep 1.5
cp /proc/$MAIN/maps /data/local/tmp/maps_race.txt 2>/dev/null
echo "MAPS_COPIED pid=$MAIN"
for p in $(pidof com.penti.app); do
  c=$(cat /proc/$p/cmdline 2>/dev/null | tr -d '\0')
  echo "ALIVE $p $c"
done
