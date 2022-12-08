#! /bin/bash
# starts up the IoT entities and a relay
# do "killall app2" to terminate 

DCT_LOCALHOST_MULTICAST=1
export DCT_LOCALHOST_MULTICAST

# ids=(frontdoor bob gate alice backdoor patio)
ids=(frontdoor gate)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 1000 hmIoT/$i.bundle &
  echo -n " starting $i"
  sleep 1
done
echo

./basicRelay -l " hmIoT/home.l.bundle,34567 hmIoT/home.e.bundle" &
echo -n " starting home basicRelay"
echo ""

