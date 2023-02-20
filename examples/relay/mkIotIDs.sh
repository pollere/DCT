#! /bin/bash
# mkIDs schema - script to create id bundles needed to run an app with some iot mbps schema
# Creates bundles for operators and devices in multicast subdomains
# and a "sub" schema, iote.trust for a relay's external unicast (UDP) subdomain 
# Publications are secured across the trust domain with signed AEAD with their cAdds ("wire" PDUs)
# signed via EdDSA and the externally unicast PDUs (cAdds/"wire") are secured with AEAD.
#  'schema' is the filename of the schema's .trust file
PATH=../../../tools:$PATH

device=(frontdoor backdoor gate patio)
operator=(alice bob roamOp)
relay=(home away)

if [ -z "$1" ]; then echo "-$0: must supply a .trust schema filename"; exit 1; fi;
if [ ! -r "$1" ]; then echo "-$0: file $1 not readable"; exit 1; fi;

Schema=${1##*/}
Schema=${Schema%.trust}
Bschema=$Schema.scm
Eschema=iote.scm
RootCert=iot.root
SchemaCert=$Schema.schema
KMCapCert=
KMPCapCert=
DeviceSigner=$RootCert
RelaySigner=$RootCert

schemaCompile -o $Bschema $1
schemaCompile -o $Eschema ../iote.trust

PubPrefix=iot
CertValidator=EdDSA

make_cert -s $CertValidator -o $RootCert $PubPrefix
schema_cert -o $SchemaCert $Bschema $RootCert
schema_cert -o iote.schema $Eschema $RootCert

if [[ $(schema_info -t $Bschema "#pubValidator") != $(schema_info -t $Eschema "#pubValidator") ]]; then
	echo
	echo "- error: pubValidator must be identical across the Trust Domain"
	exit 1;
fi;

#
# This part is for the multicast subdomains (that use Bschema)
#
if [[ $(schema_info -t $Bschema "#wireValidator") =~ AEAD|PPAEAD|PPSIGN ]]; then
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

if [[ $(schema_info -t $Bschema "#pubValidator") =~ AEADSGN|PPSIGN ]]; then
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

# make the device certs
for nm in ${device[@]}; do
    make_cert -s $CertValidator -o $nm.cert $PubPrefix/device/$nm $DeviceSigner
done

# make the operator certs
for nm in ${operator[@]}; do
    make_cert -s $CertValidator -o $nm.cert $PubPrefix/operator/$nm $RootCert
done

# The schema signing certs are signed by the root cert.
# Each identity's bundle consist of the root cert, the schema cert and the
# role cert, in that order. The "+" on the role cert indicates that its
# signing key should be included in the bundle.
# The other certs don't (and shouldn't) have signing keys.

# make the ID bundles. If the schema uses AEAD encryption, devices are
# given "KM (Key Maker) capability but not operators. 
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
# in this example, the relays can never be keymakers for the multicast subdomain's wireValidator
for nm in ${relay[@]}; do
    make_cert -s $CertValidator -o $nm.l.cert $PubPrefix/relay/$nm.l $RootCert
    make_bundle -v -o $nm.l.bundle $RootCert $SchemaCert +$nm.l.cert
done

#
# This part is for the external unicast subdomains (that uses Eschema)
# In this example, at least one external relay link will need to be a
# keymaker for the wireValidator of that subdomain
#
KMCapCert=
if [[ $(schema_info -t $Eschema "#wireValidator") =~ AEAD|PPAEAD|PPSIGN ]]; then
    if [ -z $(schema_info -c $Eschema "KM") ]; then
	echo
	echo "- error: AEAD PDU encryption requires entity(s) with a KM (KeyMaker) Capability"
	echo "         but schema $1 doesn't have any."
	exit 1;
    fi;
    # make a 'key maker' capability cert for the external subdomain
    KMCapCert=kme.cap
    make_cert -s $CertValidator -o $KMCapCert $PubPrefix/CAP/KM/1 $RootCert
    RelaySigner=$KMCapCert
fi;

# make the relay external link certs and bundles
for nm in ${relay[@]}; do
    if [ -n "$KMCapCert" ]; then
    make_cert -s $CertValidator -o $nm.e.cert $PubPrefix/relay/$nm.e $KMCapCert
    make_bundle -v -o $nm.e.bundle $RootCert iote.schema $KMCapCert +$nm.e.cert
    else
    make_cert -s $CertValidator -o $nm.e.cert $PubPrefix/relay/$nm.e $RootCert
    make_bundle -v -o $nm.e.bundle $RootCert iote.schema +$nm.e.cert
    fi
done
