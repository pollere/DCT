#! /bin/bash
# starts up all the rooms
# do "killall room" to terminate the rooms

DCT_MULTICAST_ADDR=ff01::1234
export DCT_MULTICAST_ADDR

rooms=(room1 room2 room3 room4 confRm hall)

for rm in ${rooms[@]}; do
  ./room id/$rm.bundle &
  echo -n " $rm"
  sleep 1
done
echo
