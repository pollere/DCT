#! /bin/bash
# starts up all the location reporters
# do "killall loc" to terminate them

locRs=(locRptr1 locRptr2 locRptr3 locRptr4 locRptr5)

for lr in ${locRs[@]}; do
  ./loc bundles/$lr.bundle &
  echo -n " $lr"
  sleep 1
done
echo
