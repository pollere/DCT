#! /bin/bash
# starts up the IoT entities and a relay
# do "killall relay" to terminate 

# these lines set the multicast address to be used
DCT_MULTICAST_ADDR=ff02::5678
export DCT_MULTICAST_ADDR

ids=(gate)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 10 home/$i.bundle &
  echo -n " starting $i"
  sleep 1
done
echo

echo -n " starting roamOp"
../hmIot/app3 -n 10 home/roamOp.bundle &

# use this line with "awayhostname" set to your away host for separate machines
./relay -l " home/away.l.bundle,<awayhostname>:34567 home/away.e.bundle" &
# use this line for testing relays on the same machine and using tcp for the unicast link
# ./relay -l " home/away.l.bundle,tcp:127.0.0.1:34567 home/away.e.bundle" &
echo -n " starting away relay"
echo

