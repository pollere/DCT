#! /bin/bash
# starts up all the location reporters
# do "killall loc" to terminate them
# use "-n0" to run forever. Or set to some number
# other than 10 (default)

locRs=(locRptr1 locRptr2 locRptr3 locRptr4 locRptr5 locRptr6 locRptr7 locRptr8 locRptr9)

mon bund/monitor1.bundle &

for lr in ${locRs[@]}; do
  ./loc bund/$lr.bundle &
  echo -n " $lr"
  echo
#  sleep 1
done
echo
