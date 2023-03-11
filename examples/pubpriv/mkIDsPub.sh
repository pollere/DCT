#! /bin/bash
# mkIDs schema - script to create id bundles needed to run location reporter example
# uses PPSIGN for publisher privacy of Publications
# may use AEAD or EdDSA for cAdd privacy/signing
#  'schema' is the filename of the schema's .trust file
PATH=../../../tools:$PATH

numLR=9
numMon=2

if [ -z "$1" ]; then echo "-$0: must supply a .trust schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.trust}
Bschema=$Schema.scm
RootCert=$Schema.root
SchemaCert=$Schema.schema
KMCapCert=
KMPCapCert=
SGCapCert=
IDSigner=$RootCert

schemaCompile -o $Bschema $1

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=$(schema_info $Bschema "#pubPrefix");
PubValidator=$(schema_info -t $Bschema "#pubValidator");
# CertValidator=$(schema_info -t $Bschema "#certValidator");
# default value
CertValidator=EdDSA

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert

if [[ $(schema_info -t $Bschema "#wireValidator") =~ AEAD ]]; then
    if [ -z $(schema_info -c $Bschema "KM") ]; then
        echo
        echo "- error: AEAD PDU encryption requires entity(s) with a KM (KeyMaker) Capability"
        echo "         but schema $1 doesn't have any."
        exit 1;
    fi;
    # make the 'key maker' capability cert
    KMCapCert=km.cap
    make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
    IDSigner=$KMCapCert
fi;

# PPAEAD and PPSIGN require a subscription group capability cert.
# There must be at least one SG member (SG capability)
# in this cert so that there is at least on key maker
# Here, just setting all SG members to be potential key makers.

KMPCapCert=kmp.cap
make_cert -s $CertValidator -o $KMPCapCert $PubPrefix/CAP/KMP/1 $IDSigner
# make the 'subscriber group' capability cert (with ability to be a key maker)
SGCapCert=sg.cap
make_cert -s $CertValidator -o $SGCapCert $PubPrefix/CAP/SG/pubs $KMPCapCert

# make the location reporter certs (can't be keymakers)
for (( n=1; n <= $numLR; ++n )); do
    make_cert -s $CertValidator -o locR$n.cert $PubPrefix/locRptr/$n $RootCert
done

# make the monitor certs
# if there's a subscriber group, putting all the monitors in it
for (( n=1; n <= $numMon; ++n )); do
    if [ -n $SGCapCert ]; then
        make_cert -s $CertValidator -o mon$n.cert $PubPrefix/monitor/$n $SGCapCert
    else
        make_cert -s $CertValidator -o mon$n.cert $PubPrefix/monitor/$n $IDSignerCert
    fi;
done

# The schema signing certs are signed by the root cert.
# Each identity's bundle consist of the root cert, the schema cert and the
# role cert, in that order. The "+" on the role cert indicates that its
# signing key should be included in the bundle.
# The other certs don't (and shouldn't) have signing keys.

# make the ID bundles. Only monitors given "SG" (subscriber group) capability 
for (( n=1; n <= $numLR; ++n )); do
    make_bundle -v -o locRptr$n.bundle $RootCert $SchemaCert +locR$n.cert
done

for (( n=1; n <= $numMon; ++n )); do
    if [ -n "$KMCapCert" ]; then
        if [ -n "$SGCapCert" ]; then
	        make_bundle -v -o monitor$n.bundle $RootCert $SchemaCert $KMCapCert $KMPCapCert $SGCapCert +mon$n.cert
        else
	        make_bundle -v -o monitor$n.bundle $RootCert $SchemaCert $KMCapCert +mon$n.cert
        fi;
    elif [ -n "$SGCapCert" ]; then
	    make_bundle -v -o monitor$n.bundle $RootCert $SchemaCert $KMPCapCert $SGCapCert +mon$n.cert
    else
	    make_bundle -v -o monitor$n.bundle $RootCert $SchemaCert +mon$n.cert
    fi;
done
