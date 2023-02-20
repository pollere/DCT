#! /bin/bash
# mkIDs schema - script to create id bundles needed to run an 'office' app
#  'schema' is the filename of the schema's .trust file
#  run the script from a subdirectory you set up to keep ids (ex: id under office)
PATH=../../../tools:$PATH

# room names; rooms are paired with people in correponding list order,
# rooms[0] with emp[0], etc. All the emp are done then all the mgr.
# the guard is given room "all". no one gets confRm or hall but they
# have certs to sign their controller's cert..
rooms=(room1 room2 room3 room4 confRm hall)
people=(bob emily herb alice frank)

if [ -z "$1" ]; then echo "-$0: must supply a .trust schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.trust}
Bschema=$Schema.scm
RootCert=$Schema.root
SchemaCert=$Schema.schema
ConfigCert=$Schema.config

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

# make the config cert then room certs
make_cert -s $CertValidator -o $ConfigCert $PubPrefix/config/ITwiz $RootCert

# cert for each room and a controller for each room, signed by the room cert
for nm in ${rooms[@]}; do
    make_cert -s $CertValidator -o $nm.cert $PubPrefix/room/$nm $ConfigCert
    make_cert -s $CertValidator -o ctlr.$nm.cert $PubPrefix/controller/$nm $nm.cert
done

# make the role certs; 'ri' tracks the room index for assigning people
# to rooms
let ri=0
for nm in ${people[@]}; do
    make_cert -s $CertValidator -o $nm.cert $PubPrefix/person/$nm ${rooms[$ri]}.cert
    let ri++
done

# make the room controller ID bundles
for nm in ${rooms[@]}; do
    make_bundle -v -o $nm.bundle $RootCert $SchemaCert $ConfigCert $nm.cert +ctlr.$nm.cert
done

# make the people bundles
let ri=0
for nm in ${people[@]}; do
    make_bundle -v -o $nm.bundle $RootCert $SchemaCert $ConfigCert ${rooms[$ri]}.cert +$nm.cert
    let ri++
done
