#! /bin/bash
# mkIDs schema - script to create id bundles needed to run the mesh with sensors
#  'schema' is the filename of the schema's .trust file
PATH=../../../tools:$PATH

sensor=(1 2 3 4 5 6)
relay=(1 2 3)

if [ -z "$1" ]; then echo "-$0: must supply a .trust schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.trust}
Bschema=$Schema.scm
RootCert=$Schema.root
SchemaCert=$Schema.schema
MeshSigner=$RootCert
KMCapCert=

schemaCompile -o $Bschema $1
schemaCompile -o sensor.scm ../sensor.trust

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=$(schema_info $Bschema "#pubPrefix");
# CertValidator=$(schema_info -t $Bschema "#certValidator");
# default value
CertValidator=EdDSA

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o sensor.schema sensor.scm $RootCert

# if main mesh schema uses AEAD must set keymaker
if [[ $(schema_info -t $Bschema "#wireValidator") =~ AEAD|AEADSGN|PPAEAD|PPSIGN ||
      $(schema_info -t $Bschema "#pubValidator") =~ AEADSGN|PPSIGN ]]; then
    if [ -z $(schema_info -c $Bschema "KM") ]; then
	echo
	echo "- error: AEAD encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    KMCapCert=km.cap
    make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
    MeshSigner=$KMCapCert
fi;

make_cert -s $CertValidator -o cntrl.cert $PubPrefix/controller/main $MeshSigner
if [ -n $KMCapCert ]; then
    make_bundle -v -o cntrl.bundle $RootCert $SchemaCert $KMCapCert +cntrl.cert
else
    make_bundle -v -o cntrl.bundle $RootCert $SchemaCert +cntrl.cert
fi;

# make the relay external link certs and bundles
# could use same signing cert for both relay ports if not using AEAD on mesh
# Gives relay a KM cert on both sides in order to work with AEADSGN pub even
# though it's not used (test should be for a KM in domain rather than subnet)
for n in ${relay[@]}; do
    if [ -n $KMCapCert ]; then
    make_cert -s $CertValidator -o mesh$n.cert $PubPrefix/relay/m$n $KMCapCert
    make_bundle -v -o mesh$n.bundle $RootCert $SchemaCert $KMCapCert +mesh$n.cert
    make_cert -s $CertValidator -o snet$n.cert $PubPrefix/relay/s$n $KMCapCert
    make_bundle -v -o snet$n.bundle $RootCert sensor.schema $KMCapCert +snet$n.cert
    else
    make_cert -s $CertValidator -o relay$n.cert $PubPrefix/relay/$n $RootCert
    make_bundle -v -o mesh$n.bundle $RootCert $SchemaCert +relay$n.cert
    make_bundle -v -o snet$n.bundle $RootCert sensor.schema +relay$n.cert
    fi
done

# make the sensor certs and bundles
for n in ${sensor[@]}; do
    make_cert -s $CertValidator -o sensor$n.cert $PubPrefix/sensor/$n $RootCert
    make_bundle -v -o sensor$n.bundle $RootCert sensor.schema +sensor$n.cert
done
