#! /bin/bash
# starts up the IoT entities and a relay
# do "killall app2" "killall basicRelay" to terminate 

# these lines are to keep the multicast traffic local to this host
DCT_LOCALHOST_MULTICAST=1
export DCT_LOCALHOST_MULTICAST

# ids=(frontdoor bob gate alice backdoor patio)
ids=(frontdoor gate bob)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 10 home/$i.bundle &
  echo -n " starting $i"
  echo ""
  sleep 1
done
echo

./basicRelay -l " home/home.l.bundle,34567 home/home.e.bundle" &
echo -n " starting home basicRelay"
echo ""

