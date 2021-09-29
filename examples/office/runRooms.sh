#! /bin/bash
# starts up all the rooms
# do "killall room" to terminate the rooms

rooms=(room1 room2 room3 room4 confRm hall)

for rm in ${rooms[@]}; do
  ./room id/$rm.bundle &
  echo -n " $rm"
  sleep 1
done
echo
