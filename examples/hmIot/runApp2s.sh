#! /bin/bash
# starts up app2s
# do "killall app2" to terminate them
# set "-n xxx" for a number of runs other than 10 (default)
# or "-n 0" for run forever

# members=(gate frontdoor backdoor patio bob alice)
members=(gate patio frontdoor backdoor)

#get rid of any leftovers
killall app2
DCT_DEFAULT_IF=en0
export DCT_DEFAULT_IF
for mbr in ${members[@]}; do
  ./app2 -n 4 id1/$mbr.bundle &
  echo -n " $mbr"
  echo
#  sleep .1 
done
echo
