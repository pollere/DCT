#! /bin/bash
# starts up the IoT entities and a relay
# do "killall app2" "killall relay" to terminate 

DCT_DEFAULT_IF=en0
export DCT_DEFAULT_IF

DCT_MULTICAST_ADDR=ff01::1234
export DCT_MULTICAST_ADDR

# ids=(frontdoor bob gate alice backdoor patio)
ids=(frontdoor backdoor patio)

for i in ${ids[@]}; do
  ../hmIot/app2 -n 0 r3tst/$i.bundle &
  echo -n " starting $i"
  echo ""
  sleep 1
done
echo

./relay -l "r3tst/homeLoc.bundle,r3tst/homeExt.bundle,r3tst/homeLink.bundle" &
echo -n " starting home relay"
echo ""
