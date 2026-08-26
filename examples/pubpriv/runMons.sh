#! /bin/bash
# starts up all the location reporters
# do "killall mon" to terminate them
# use "-n0" to run forever. Or set to some number
# other than 10 (default)

killall mon
DCT_DEFAULT_IF=lo0
export DCT_DEFAULT_IF
DCT_MULTICAST_ADDR=ff01::1234
export DCT_MULTICAST_ADDR

mons=(monitor1 monitor2)

for m in ${mons[@]}; do
  ./mon bundles/$m.bundle &
  echo -n " $m"
  echo
#  sleep 1
done
echo
