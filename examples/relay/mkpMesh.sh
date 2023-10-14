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
RootCert=$Schema.root
SchemaCert=$Schema.schema
PubKMSigner=$RootCert
KMPCapCert=
RLYCapCert=

schemaCompile -o $Bschema $1
schemaCompile -o psensor.scm ../psensor.rules

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=mesh
CertValidator=$(schema_info -t $Bschema "#certValidator");
RootCert=mesh.root

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o psensor.schema psensor.scm $RootCert

# if schema uses AEADSGN for Pubs must set Pub keymaker
if [[ $(schema_info -t $Bschema "#msgsValidator") =~ AEADSGN|PPSIGN ]]; then
    if [ -z $(schema_info -c $Bschema "KMP") ]; then
	echo
	echo "- error: AEAD Pub encryption requires entity(s) with a KMP (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    KMPCapCert=kmp.cap
    make_cert -s $CertValidator -o $KMPCapCert $PubPrefix/CAP/KMP/1 $RootCert
    PubKMSigner=$KMPCapCert
fi;

make_cert -s $CertValidator -o cntrl.cert $PubPrefix/controller/main $PubKMSigner
if [ -n $KMPCapCert ]; then
    make_bundle -v -o cntrl.bundle $RootCert $SchemaCert $KMPCapCert +cntrl.cert
else
    make_bundle -v -o cntrl.bundle $RootCert $SchemaCert +cntrl.cert
fi;


# make the relay certs and bundles
# use same signing cert for both relay ports
RLYCapCert=rly.cap
make_cert -s $CertValidator -o $RLYCapCert $PubPrefix/CAP/RLY/default $RootCert
for n in ${relay[@]}; do
    make_cert -s $CertValidator -o mesh$n.cert $PubPrefix/relay/m$n $RLYCapCert
    make_cert -s $CertValidator -o snet$n.cert $PubPrefix/relay/s$n $RLYCapCert
    make_bundle -v -o mesh$n.bundle $RootCert $SchemaCert $RLYCapCert +mesh$n.cert
    make_bundle -v -o snet$n.bundle $RootCert psensor.schema $RLYCapCert +snet$n.cert
done

# make the sensor certs and bundles
for n in ${sensor[@]}; do
    make_cert -s $CertValidator -o sensor$n.cert $PubPrefix/sensor/$n $RootCert
    make_bundle -v -o sensor$n.bundle $RootCert psensor.schema +sensor$n.cert
done
