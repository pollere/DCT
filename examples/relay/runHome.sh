#! /bin/bash
# starts up the IoT entities and a relay
# do "killall app2" "killall relay" to terminate 

# ids=(frontdoor bob gate alice backdoor patio)
ids=(frontdoor backdoor)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 0 home/$i.bundle &
  echo -n " starting $i"
  echo ""
  sleep 1
done
echo

./relay -l " home/home.l.bundle,tcp:34567 home/home.e.bundle" &
echo -n " starting home relay"
echo ""


