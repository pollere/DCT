#! /bin/bash
# starts up all the relays and sensors
# do "killall sensors" to terminate the sensors

relays=(1 2 3)

for r in ${relays[@]}; do
  ./basicRelay -l " mesh/mesh$r.bundle, mesh/snet$r.bundle" &
  echo -n " starting basicRelay$r"
  sleep 1
done
echo

sensors=(sensor1 sensor2 sensor3 sensor4 sensor5)

for s in ${sensors[@]}; do
  ./sens mesh/$s.bundle &
  echo -n " starting $s"
  sleep 1
done
echo
