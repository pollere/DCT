#! /bin/bash
# starts up all the location reporters
# do "killall loc" to terminate them
# use "-n0" to run forever. Or set to some number
# other than 10 (default)

DCT_DEFAULT_IF=en0
export DCT_DEFAULT_IF
DCT_MULTICAST_ADDR=ff02::1234
export DCT_MULTICAST_ADDR

locRs=(locRptr1 locRptr2 locRptr3 locRptr4 locRptr5 locRptr6 locRptr7 locRptr8 locRptr9)

for lr in ${locRs[@]}; do
  ./loc bundles/$lr.bundle &
  echo -n " $lr"
  echo
#  sleep 1
done
echo
