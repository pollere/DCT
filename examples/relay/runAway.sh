#! /bin/bash
# starts up the IoT entities and a relay
# do "killall basicRelay" to terminate 

# these lines are to keep the multicast traffic local to this host
DCT_LOCALHOST_MULTICAST=1
export DCT_LOCALHOST_MULTICAST

ids=(gate)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 1000 hmIoT/$i.bundle &
  echo -n " starting $i"
  sleep 1
done
echo

./basicRelay -l " home/away.l.bundle,<awayhostname>:34567 home/away.e.bundle" &
echo -n " starting away basicRelay"
sleep 1
echo

../hmIot/app4 -n 1000 home/roamOp.bundle &
echo -n " starting roamOp"

