# Location Reporter Example for Robustness Testing

This example is for experiments with the features of syncps that allow for robust meshing, i.e. allowing a member to resend Publications originated by a different member while avoiding broadcast storms. This is for networks where all members are not in-range and/or where some members may sleep or otherwise be intermittent. Simple testing of this can be carried out using a hack to the library's transport.hpp file that creates pseudo topologies on top of a fully connected broadcast channel. The approach relies on sorting source ids (IP address and port) then using the sorted array to decide which senders can be "heard" by any receiver. Two approaches have been implemented, one where members only hear adjacent members and one that splits the  array into two overlapping parts: from 0 to (#members)/2 + 1 and (#members)/2 to the end of the array. The latter can be used to illustrate both republishing and also refraining from republishing more than once. The algorithm is selected by MESHTEST as defined in the Makefile (0 for the physical connectivity, 1 for adjacent-only, and 2 for two overlapping groups).

The confident programmer/tester can add more cases in include/dct/face/transport.hpp.

There are two types of applications: a location reporter that periodically publishes pseudo coordinates and a monitor that subscribes to these location reports. The loc.rules uses AEAD encryption on cAdds, EdDSA signing on Publications.

#### Running the example

First, use included script and schema to make identity bundles

```
mkdir bund
cd bund
../mkIDs.sh ../loc.rules
cd ..
```

In a terminal window:

`runLocrs.sh` 

There should be a short delay and then some command line output. Use of **dctwatch** in another window lets you observe the packets. You will have to kill the mon process manually.

#### Note

Any of the other DCT/examples directories can be used with a non-fully-connected pseudo topology by setting MESHTEST in the Makefile. The loc/mon example is just one that is easy to expand to a larger number of members.

Copyright (C) 2022-3 Pollere LLC
