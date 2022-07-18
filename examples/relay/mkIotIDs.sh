#! /bin/bash
# mkIDs schema - script to create id bundles needed to run an app with some iot mbps schema
# and a "sub" schema, iote.trust for a relay's "external" connection
#  'schema' is the filename of the schema's .trust file
PATH=../../../tools:$PATH

device=(frontdoor backdoor gate)
operator=(alice bob roamOp)
relay=(home away)

if [ -z "$1" ]; then echo "-$0: must supply a .trust schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.trust}
Bschema=$Schema.scm
RootCert=$Schema.root
SchemaCert=$Schema.schema
KMCapCert=

schemaCompile -o $Bschema $1
schemaCompile -o iote.scm ../iote.trust
# for testing on same multicast network - "away" network

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=$(schema_info $Bschema "#pubPrefix");
PubValidator=$(schema_info -t $Bschema "#pubValidator");

make_cert -s $PubValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o iote.schema iote.scm $RootCert

# make the device certs
for nm in ${device[@]}; do
    make_cert -s $PubValidator -o $nm.cert $PubPrefix/device/$nm $RootCert
done

# make the operator certs
for nm in ${operator[@]}; do
    make_cert -s $PubValidator -o $nm.cert $PubPrefix/operator/$nm $RootCert
done

# this is for the remote link -  iote.trust can use different cAdd Validator
# if AEAD must set keymaker
Eschema=iote.scm
if [ $(schema_info -t $Eschema "#wireValidator") == AEAD ]; then
    if [ -z $(schema_info -c $Eschema "KM") ]; then
	echo
	echo "- error: AEAD encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema iote.trust doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    KMCapCert=km.cap
    RelaySigner=$KMCapCert
    make_cert -s $PubValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
fi;

# make the relay external link certs and bundles
for nm in ${relay[@]}; do
    if [ -n $KMCapCert ]; then
    make_cert -s $PubValidator -o $nm.e.cert $PubPrefix/relay/$nm.e $KMCapCert
    make_bundle -v -o $nm.e.bundle $RootCert iote.schema $KMCapCert +$nm.e.cert
    else
    make_cert -s $PubValidator -o $nm.e.cert $PubPrefix/relay/$nm.e $RootCert
    make_bundle -v -o $nm.e.bundle $RootCert iote.schema +$nm.e.cert
    fi
done
# make the relay certs and bundles for local interfaces
for nm in ${relay[@]}; do
    make_cert -s $PubValidator -o $nm.l.cert $PubPrefix/relay/$nm.l $RootCert
    make_bundle -v -o $nm.l.bundle $RootCert $SchemaCert +$nm.l.cert
done

# The schema signing certs are signed by the root cert.
# Each identity's bundle consist of the root cert, the schema cert and the
# role cert, in that order. The "+" on the role cert indicates that its
# signing key should be included in the bundle.
# The other certs don't (and shouldn't) have signing keys.

# make the ID bundles
for nm in ${operator[@]} ${device[@]}; do
    make_bundle -v -o $nm.bundle $RootCert $SchemaCert +$nm.cert
done
