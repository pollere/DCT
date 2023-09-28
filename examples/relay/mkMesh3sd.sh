#! /bin/bash
# mkIDs schema - script to create id bundles needed to run the mesh with sensors
# this version sets up three separate subdomains on a local multicast network
#  'schema' is the filename of the schema's .rules file
PATH=../../../tools:$PATH

sensor=(1 2 3 4 5 6)
relay=(1 2 3)

if [ -z "$1" ]; then echo "-$0: must supply a .rules schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.rules}
Bschema=$Schema.scm
SchemaCert=$Schema.schema
KMCapCert=
RLYCapCert=

schemaCompile -o $Bschema $1
# subschemas
schemaCompile -o sensor.scm ../sensor.rules
schemaCompile -o cntrlr.scm ../cntrlr.rules

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=mesh
# CertValidator=$(schema_info -t $Bschema "#certValidator");
# default value
CertValidator=EdDSA
RootCert=mesh.root

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o sensor.schema sensor.scm $RootCert
schema_cert -o cntrlr.schema cntrlr.scm $RootCert

# if main mesh schema uses AEAD must set keymaker
# (main mesh gives relays KM capability)
RLYMCapCert=rlyM.cap
if [[ $(schema_info -t $Bschema "#wireValidator") =~ AEAD|AEADSGN|PPAEAD|PPSIGN ]]; then
    if [ -z $(schema_info -c $Bschema "KM") ]; then
	echo
	echo "- error: AEAD encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    KMCapCert=km.cap
    make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
    make_cert -s $CertValidator -o $RLYMCapCert $PubPrefix/CAP/RLY/defM $KMCapCert
else
    make_cert -s $CertValidator -o $RLYMCapCert $PubPrefix/CAP/RLY/defM $RootCert
fi;
# make the relay cap cert for the sensor subnet
make_cert -s $CertValidator -o rlyS.cap $PubPrefix/CAP/RLY/defS $RootCert

# make the relay certs and bundles
# isn't used on sensor side
for n in ${relay[@]}; do
    make_cert -s $CertValidator -o mesh$n.cert $PubPrefix/relay/m$n $RLYMCapCert
    make_cert -s $CertValidator -o snet$n.cert $PubPrefix/relay/s$n rlyS.cap
    make_bundle -v -o mesh$n.bundle $RootCert $SchemaCert $KMCapCert $RLYMCapCert +mesh$n.cert
    make_bundle -v -o snet$n.bundle $RootCert sensor.schema rlyS.cap +snet$n.cert
done

# relay-to-controller connection - for relay 1
make_cert -s $CertValidator -o rlyC.cap $PubPrefix/CAP/RLY/defC $KMCapCert
make_cert -s $CertValidator -o clink.cert $PubPrefix/relay/c rlyC.cap
make_cert -s $CertValidator -o cntrl.cert $PubPrefix/controller/main $RootCert
make_bundle -v -o cntrl.bundle $RootCert cntrlr.schema +cntrl.cert
make_bundle -v -o clink.bundle $RootCert cntrlr.schema $KMCapCert rlyC.cap +clink.cert

# make the sensor certs and bundles
for n in ${sensor[@]}; do
    make_cert -s $CertValidator -o sensor$n.cert $PubPrefix/sensor/$n $RootCert
    make_bundle -v -o sensor$n.bundle $RootCert sensor.schema +sensor$n.cert
done
