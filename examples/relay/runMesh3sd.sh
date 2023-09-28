#! /bin/bash
# starts up all the relays and sensors
# sensors have trust schema compatible with the s<n> deftt of the relays
# the m<n> side of the relays are compatible with the controller
# do "killall sens" to terminate the sensors
# start cntrl rtst/cntrl.bundle in another window

./relay -l "rtst/mesh1.bundle,rtst/snet1.bundle,rtst/clink.bundle" &
echo -n " starting relay1"
echo
relays=(2 3)
for r in ${relays[@]}; do
  ./relay -l "rtst/mesh$r.bundle,rtst/snet$r.bundle" &
  echo -n " starting relay$r"
  echo -n " "
  sleep 1
done
echo

sensors=(sensor1 sensor2 sensor3 sensor4 sensor5)

for s in ${sensors[@]}; do
  ./sens -n0 rtst/$s.bundle &
  echo -n " starting $s"
  echo -n " "
  sleep 1
done
echo
