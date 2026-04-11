#! /bin/bash
# starts up all the rooms
# do "killall room" to terminate the rooms

DCT_MULTICAST_ADDR=ff01::1234
export DCT_MULTICAST_ADDR

./phone id/bob.bundle light on
echo -n " bob signals light on"
sleep 1
./phone id/bob.bundle confRm light on
echo -n " bob signals confRm light on"
sleep 1
./phone id/alice.bundle confRm light on
echo -n " alice signals confRm light on"
