#! /bin/bash
# mkIDs schema - script to create id bundles needed to run an app with some mbps schema
#  'schema' is the filename of the schema's .trust file
#  run the script from a subdirectory you set up to keep ids (ex: id under office)
PATH=../../../tools:$PATH

# room names; rooms are paired with people in correponding list order,
# rooms[0] with emp[0], etc. All the emp are done then all the mgr.
# the guard is given room "all". no one gets confRm or hall but they
# have certs to sign their controller's cert..
rooms=(room1 room2 room3 room4 all confRm hall)
emp=(bob emily herb)
mgr=(alice)
grd=(frank)

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

make_cert -s $PubValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert

# make the config cert then room certs
make_cert -s $PubValidator -o $ConfigCert $PubPrefix/config/ITwiz $RootCert

for nm in ${rooms[@]}; do
        make_cert -s $PubValidator -o $nm.cert $PubPrefix/room/$nm $ConfigCert
    if [ $nm != "all" ]; then
        make_cert -s $PubValidator -o ctlr.$nm.cert $PubPrefix/controller/$nm $nm.cert
    fi
done

# make the emp, mgr and grd certs; 'ri' tracks the room index for assigning people
# to rooms
let ri=0
for nm in ${emp[@]}; do
    make_cert -s $PubValidator -o $nm.cert $PubPrefix/employee/$nm ${rooms[$ri]}.cert
    let ri++
done
for nm in ${mgr[@]}; do
    make_cert -s $PubValidator -o $nm.cert $PubPrefix/manager/$nm ${rooms[$ri]}.cert
    let ri++
done
for nm in ${grd[@]}; do
    make_cert -s $PubValidator -o $nm.cert $PubPrefix/guard/$nm ${rooms[$ri]}.cert
done

# make the room controller ID bundles
for nm in ${rooms[@]}; do
    if [ $nm != "all" ]; then
        make_bundle -v -o $nm.bundle $RootCert $SchemaCert $ConfigCert $nm.cert +ctlr.$nm.cert
    fi
done

# make the emp/mgr/grd bundles
let ri=0
for nm in ${emp[@]} ${mgr[@]} ${grd[@]}; do
    make_bundle -v -o $nm.bundle $RootCert $SchemaCert $ConfigCert ${rooms[$ri]}.cert +$nm.cert
    let ri++
done
