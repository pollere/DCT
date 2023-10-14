#! /bin/bash
# mkIDs schema - script to create id bundles needed to run an app with some iot mbps schema
# Creates bundles for operators and devices in multicast subdomains
# and a "sub" schema, iote.rules for a relay's external unicast (UDP) subdomain 
# Publications are secured across the trust domain with signed AEAD with their cAdds (PDUs)
# signed via EdDSA and the externally unicast PDUs (cAdds) are secured with AEAD.
#  'schema' is the filename of the schema's .rules file
PATH=../../../tools:$PATH

device=(frontdoor backdoor gate patio)
operator=(alice bob roamOp)
# the first relay will be the server side for external link
relay=(home away)

if [ -z "$1" ]; then echo "-$0: must supply a .rules schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.rules}
Bschema=$Schema.scm
Eschema=iote.scm
RootCert=iot.root
SchemaCert=$Schema.schema
KMCapCert=
KMPCapCert=
DeviceSigner=$RootCert

schemaCompile -o $Bschema $1
schemaCompile -o $Eschema ../iote.rules

PubPrefix=iot
CertValidator=$(schema_info -t $Bschema "#certValidator");
LLM=llm:ff02::1234
PROTO=udp:
PORT=34567
SRVR=<IPaddress:>

echo $PROTO$SRVR$PORT

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o iote.schema $Eschema $RootCert

if [[ $(schema_info -t $Bschema "#msgsValidator") != $(schema_info -t $Eschema "#msgsValidator") ]]; then
	echo
	echo "- error: msgsValidator must be identical across the Trust Domain"
	exit 1;
fi;

#
# This part makes certs needed for member deftts of the multicast subdomains (that use Bschema)
#
if [[ $(schema_info -t $Bschema "#pduValidator") =~ AEAD|PPAEAD|PPSIGN ]]; then
    if [ -z $(schema_info -c $Bschema "KM") ]; then
	echo
	echo "- error: AEAD PDU encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    KMCapCert=kml.cap
    make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
    DeviceSigner=$KMCapCert
fi;

if [[ $(schema_info -t $Bschema "#msgsValidator") =~ AEADSGN|PPSIGN ]]; then
    if [ -z $(schema_info -c $Bschema "KMP") ]; then
	echo
	echo "- error: AEAD Pub encryption requires entity(s) with a KMP (KeyMaker Pubs) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make the 'key maker' capability cert
    # This cert should be signed by the KMCapCert, if any, and otherwise the RootCert.
    # The code above set DeviceSigner to the correct choice so its value is used as
    # this cert's signer then DeviceSigner is updated so devices are signed by the KMPCapCert.
    KMPCapCert=kmp.cap
    make_cert -s $CertValidator -o $KMPCapCert $PubPrefix/CAP/KMP/1 $DeviceSigner
    DeviceSigner=$KMPCapCert
fi;

LocRelayCap=locRly.cap
# make a local multicast relay capability cert (assumes same for both local subnets)
make_cert -s $CertValidator -o $LocRelayCap $PubPrefix/CAP/RLY/$LLM $RootCert

# make the device identity certs
for nm in ${device[@]}; do
    make_cert -s $CertValidator -o $nm.cert $PubPrefix/device/$nm $DeviceSigner
done

# make the operator identity certs
for nm in ${operator[@]}; do
    make_cert -s $CertValidator -o $nm.cert $PubPrefix/operator/$nm $RootCert
done

# The schema signing certs are signed by the root cert.
# Each identity's bundle consist of the root cert, the schema cert and the
# role cert, in that order. The "+" on the role cert indicates that its
# signing key should be included in the bundle.
# The other certs don't (and shouldn't) have signing keys.

# make the ID bundles. If the schema uses AEAD encryption, devices are
# given "KM (Key Maker) capability while operators are not. 
for nm in ${operator[@]}; do
    make_bundle -v -o $nm.bundle $RootCert $SchemaCert +$nm.cert
done

for nm in ${device[@]}; do
    if [ -n "$KMCapCert" -a -n "$KMPCapCert" ]; then
	make_bundle -v -o $nm.bundle $RootCert $SchemaCert $KMCapCert $KMPCapCert +$nm.cert
    elif [ -n "$KMCapCert" ]; then
	make_bundle -v -o $nm.bundle $RootCert $SchemaCert $KMCapCert +$nm.cert
    elif [ -n "$KMPCapCert" ]; then
	make_bundle -v -o $nm.bundle $RootCert $SchemaCert $KMPCapCert +$nm.cert
    else
	make_bundle -v -o $nm.bundle $RootCert $SchemaCert +$nm.cert
    fi;
done

# make the relay certs and bundles for local interfaces
# in this example, the relays can never be keymakers for the multicast subdomain's pduValidator
# so the Loc Relay capability cert is signed by the RootCert
subdom=Loc
for nm in ${relay[@]}; do
    echo $nm$subdom
    make_cert -s $CertValidator -o $nm$subdom.cert $PubPrefix/relay/$nm$subdom $LocRelayCap
    make_bundle -v -o $nm$subdom.bundle $RootCert $SchemaCert $LocRelayCap +$nm$subdom.cert
done

#
# This part is for the external unicast subdomains (that uses Eschema)
# In this example, at least one external relay link will need to be a
# keymaker for the pduValidator of that subdomain
KMCapCert=
if [[ $(schema_info -t $Eschema "#pduValidator") =~ AEAD|PPAEAD|PPSIGN ]]; then
    if [ -z $(schema_info -c $Eschema "KM") ]; then
	echo
	echo "- error: AEAD PDU encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make a 'key maker' capability cert for the external subdomain
    KMCapCert=km.cap
    make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
fi;
# Need relay certs for both the client and server ends of the unicast link
# make external relay capability certs (client and server)
#
RelayCert=rlySrvr.cap
ADDR=$PROTO$PORT
subdom=Ext
# make the relay external link certs and bundles
for nm in ${relay[@]}; do
    echo $nm$subdom
    if [ -n "$KMCapCert" ]; then
    make_cert -s $CertValidator -o $RelayCert $PubPrefix/CAP/RLY/$ADDR $KMCapCert
    make_cert -s $CertValidator -o $nm$subdom.cert $PubPrefix/relay/$nm$subdom $RelayCert
    make_bundle -v -o $nm$subdom.bundle $RootCert iote.schema $KMCapCert $RelayCert +$nm$subdom.cert
    else
    make_cert -s $CertValidator -o $RelayCert $PubPrefix/CAP/RLY/$ADDR $RootCert
    make_cert -s $CertValidator -o $nm$subdom.cert $PubPrefix/relay/$nm$subdom $RelayCert
    make_bundle -v -o $nm$subdom.bundle $RootCert iote.schema $RelayCert +$nm$subdom.cert
    fi
    ADDR=$PROTO$SRVR$PORT #client needs the server address
    RelayCert=rlyClient.cap
done
