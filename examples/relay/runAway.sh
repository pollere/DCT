#! /bin/bash
# starts up the IoT entities and a relay
# do "killall relay" to terminate 

DCT_DEFAULT_IF=enp2s0
export DCT_DEFAULT_IF

# these lines set the multicast address to be used
DCT_MULTICAST_ADDR=ff02::5678
export DCT_MULTICAST_ADDR

ids=(gate)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 0 -q home/$i.bundle &
  echo -n " starting $i"
  sleep 1
done
echo

echo -n " starting roamOp"
../hmIot/app3 -n 0 home/roamOp.bundle &

./relay -l "home/awayLoc.bundle,home/awayExt.bundle" &
echo -n " starting away relay"
echo
