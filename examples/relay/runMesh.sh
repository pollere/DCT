#! /bin/bash
# starts up all the relays and sensors
# sensors have trust schema compatible with the s<n> deftt of the relays
# the m<n> side of the relays are compatible with the controller
# do "killall sens" to terminate the sensors

relays=(1 2 3)

for r in ${relays[@]}; do
  ./relay -l "mesh/mesh$r.bundle,pmesh/snet$r.bundle" &
  echo -n " starting relay$r"
  echo -n " "
  sleep 1
done
echo

sensors=(sensor1 sensor2 sensor3 sensor4 sensor5)

for s in ${sensors[@]}; do
  ./sens -n0 mesh/$s.bundle &
  echo -n " starting $s"
  echo -n " "
  sleep 1
done
echo
