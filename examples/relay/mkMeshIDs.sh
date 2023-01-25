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
PubValidator=$(schema_info -t $Bschema "#pubValidator");

make_cert -s $PubValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o sensor.schema sensor.scm $RootCert


# if main mesh schema uses AEAD must set keymaker
if [ $(schema_info -t $Bschema "#wireValidator") == AEAD ]; then
    if [ -z $(schema_info -c $Bschema "KM") ]; then
	echo
	echo "- error: AEAD encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    KMCapCert=km.cap
    make_cert -s $PubValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
    MeshSigner=$KMCapCert
fi;

make_cert -s $PubValidator -o cntrl.cert $PubPrefix/controller/main $MeshSigner
if [ -n $KMCapCert ]; then
    make_bundle -v -o cntrl.bundle $RootCert $SchemaCert $KMCapCert +cntrl.cert
else
    make_bundle -v -o cntrl.bundle $RootCert $SchemaCert +cntrl.cert
fi;
# for testing
#  make_bundle -v -o cntrl.bundle $RootCert $SchemaCert +cntrl.cert

# make the relay external link certs and bundles
# could use same signing cert for both relay ports if not using AEAD on mesh
# this isn't set up to use AEAD on sensor side - doesn't give relay a KM cert
for n in ${relay[@]}; do
    if [ -n $KMCapCert ]; then
    make_cert -s $PubValidator -o mesh$n.cert $PubPrefix/relay/m$n $KMCapCert
    make_bundle -v -o mesh$n.bundle $RootCert $SchemaCert $KMCapCert +mesh$n.cert
    make_cert -s $PubValidator -o snet$n.cert $PubPrefix/relay/s$n $RootCert
    make_bundle -v -o snet$n.bundle $RootCert sensor.schema +snet$n.cert
    else
    make_cert -s $PubValidator -o relay$n.cert $PubPrefix/relay/$n $RootCert
    make_bundle -v -o mesh$n.bundle $RootCert $SchemaCert +relay$n.cert
    make_bundle -v -o snet$n.bundle $RootCert sensor.schema +relay$n.cert
    fi
done

# make the sensor certs and bundles
for n in ${sensor[@]}; do
    make_cert -s $PubValidator -o sensor$n.cert $PubPrefix/sensor/$n $RootCert
    make_bundle -v -o sensor$n.bundle $RootCert sensor.schema +sensor$n.cert
done
