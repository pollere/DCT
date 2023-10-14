#! /bin/bash
# mkIDs schema - script to create id bundles needed to run location reporter example
# for testing republishing features for robust meshes
#  'schema' is the filename of the schema's .rules file
PATH=../../../tools:$PATH

numLR=9
numMon=2

if [ -z "$1" ]; then echo "-$0: must supply a .rules schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.rules}
Bschema=$Schema.scm
RootCert=$Schema.root
SchemaCert=$Schema.schema
KMCapCert=

schemaCompile -o $Bschema $1

# extract the info needed to make certs from the compiled schema
Pub=$(schema_info $Bschema);
PubPrefix=$(schema_info $Bschema "#pubPrefix");
PubValidator=$(schema_info -t $Bschema "#msgsValidator");
CertValidator=$(schema_info -t $Bschema "#certValidator");

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert

# There must be at least one KM member (KM capability)
# in this cert so that there is at least on key maker
# Here, just setting all SG members to be potential key makers.

KMCapCert=km.cap
make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert

# make the location reporter certs
for (( n=1; n <= $numLR; ++n )); do
    make_cert -s $CertValidator -o locR$n.cert $PubPrefix/locRptr/$n $RootCert
done

# make the monitor certs
for (( n=1; n <= $numMon; ++n )); do
    make_cert -s $CertValidator -o mon$n.cert $PubPrefix/monitor/$n $KMCapCert
done

# The schema signing certs are signed by the root cert.
# Each identity's bundle consist of the root cert, the schema cert and the
# role cert, in that order. The "+" on the role cert indicates that its
# signing key should be included in the bundle.
# The other certs don't (and shouldn't) have signing keys.

# make the ID bundles. Only monitors given "KM" (keymaker) capability 
for (( n=1; n <= $numLR; ++n )); do
    make_bundle -v -o locRptr$n.bundle $RootCert $SchemaCert +locR$n.cert
done

for (( n=1; n <= $numMon; ++n )); do
    make_bundle -v -o monitor$n.bundle $RootCert $SchemaCert $KMCapCert +mon$n.cert
done
