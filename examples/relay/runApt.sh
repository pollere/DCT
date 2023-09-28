#! /bin/bash
# starts up the IoT entities and a relay
# do "killall app2" "killall relay" to terminate 

DCT_DEFAULT_IF=en0
export DCT_DEFAULT_IF

DCT_MULTICAST_ADDR=ff01::3456
export DCT_MULTICAST_ADDR

../hmIot/app2 -n 0 r3tst/frontdoor.bundle &
echo -n " starting apartment frontdoor"
echo ""

./relay -l "r3tst/aptLoc.bundle,r3tst/aptLink.bundle" &
echo -n " starting apartment relay"
echo ""
