#! /bin/bash
# starts up app2s
# do "killall app2" to terminate them
# set "-n xxx" for a number of runs other than 10 (default)
# or "-n 0" for run forever

members=(bob gate frontdoor alice backdoor patio)

for mbr in ${members[@]}; do
  ./app2 -n 5 id0/$mbr.bundle &
  echo -n " $mbr"
  echo
  sleep 1
done
echo
