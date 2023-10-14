#! /bin/bash
# mkIDs schema - script to create id bundles needed to run the mesh with sensors
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
RlySigner=$RootCert
KMCapCert=
RLYCapCert=

schemaCompile -o $Bschema $1
schemaCompile -o sensor.scm ../sensor.rules

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=mesh
CertValidator=$(schema_info -t $Bschema "#certValidator");
RootCert=mesh.root

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o sensor.schema sensor.scm $RootCert

# if main mesh schema uses AEAD must set keymaker
# (main mesh gives relays KM capability)
if [[ $(schema_info -t $Bschema "#pduValidator") =~ AEAD|AEADSGN|PPAEAD|PPSIGN ]]; then
    if [ -z $(schema_info -c $Bschema "KM") ]; then
	echo
	echo "- error: AEAD encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    KMCapCert=km.cap
    make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
    RLYCapCert=rly.cap
    make_cert -s $CertValidator -o $RLYCapCert $PubPrefix/CAP/RLY/default $KMCapCert
else
    make_cert -s $CertValidator -o $RLYCapCert $PubPrefix/CAP/RLY/default $RootCert
fi;

make_cert -s $CertValidator -o cntrl.cert $PubPrefix/controller/main $RootCert
make_bundle -v -o cntrl.bundle $RootCert $SchemaCert +cntrl.cert

# make the relay certs and bundles
# here using the same signing cert for both relay deftts even though the KM cap
# isn't used on sensor side
 # make the 'key maker' capability cert
for n in ${relay[@]}; do
    make_cert -s $CertValidator -o mesh$n.cert $PubPrefix/relay/m$n $RLYCapCert
    make_cert -s $CertValidator -o snet$n.cert $PubPrefix/relay/s$n $RLYCapCert
    make_bundle -v -o mesh$n.bundle $RootCert $SchemaCert $KMCapCert $RLYCapCert +mesh$n.cert
    make_bundle -v -o snet$n.bundle $RootCert sensor.schema $KMCapCert $RLYCapCert +snet$n.cert
done

# make the sensor certs and bundles
for n in ${sensor[@]}; do
    make_cert -s $CertValidator -o sensor$n.cert $PubPrefix/sensor/$n $RootCert
    make_bundle -v -o sensor$n.bundle $RootCert sensor.schema +sensor$n.cert
done
