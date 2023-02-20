#! /bin/bash
# starts up all the relays and sensors
# sensors have trust schema compatible with the s<n> deftt of the relays
# the m<n> side of the relays are compatible with the controller
# do "killall sensors" to terminate the sensors

relays=(1) # 2 3)

for r in ${relays[@]}; do
  ./basicRelay -l " mesh/mesh$r.bundle, mesh/snet$r.bundle" &
  echo -n " starting basicRelay$r"
  echo -n " "
  sleep 1
done
echo

sensors=(sensor1 sensor2 sensor3 sensor4 sensor5)

for s in ${sensors[@]}; do
  ./sens mesh/$s.bundle &
  echo -n " starting $s"
  echo -n " "
  sleep 1
done
echo
