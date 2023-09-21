#! /bin/bash
# starts up the IoT entities and a relay
# do "killall app2" "killall relay" to terminate 

killall relay
killall app2

DCT_DEFAULT_IF=en0
export DCT_DEFAULT_IF
DCT_MULTICAST_ADDR=ff02::1234
export DCT_MULTICAST_ADDR

# ids=(frontdoor bob gate alice backdoor patio)
ids=(frontdoor backdoor)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 0 -q tst/$i.bundle &
  echo -n " starting $i"
  echo ""
  sleep 1
done
echo

./relay -l "tst/homeLoc.bundle,tst/homeExt.bundle" &
echo -n " starting home relay"
echo ""


