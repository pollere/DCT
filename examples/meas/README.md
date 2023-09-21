# An extended trust domain for measurement

Measurement data is collected from devices at independent locations and sent to a collector at a different location. The collector issues commands for specific locations or for all locations and the devices respond to commands as well as sending periodic status reports and alerts if any measurements are outside of their expected range. Measurements are to be private; only readable by a collector. Communications from the collector are private within the domain, i.e., all devices can decrypt them.

Picture - multi-port relay with locations HQ, loc{mercury,venus,earth,mars} Connector (with relay deftts) in center, EdgeLoc*Id* (with relay deftts) at each LocId subnet

Connector is a relay element with a deftt for each location (HQ and all Loc*Ids*), each with its own identity bundle and each relaying with one of the locations. This means the (sub)schema used by each of these will be the same as that at its target location as the two will form a sync zone.

The HQ-Connector sync zone uses the entire communications schema since all the domain's Publication types are valid here. 

The domain communications ruleset needs to define the two broad types of Publications, those created and signed by a collector and those created and signed by devices. In our system, collectors will send commands and Publications that carry information to set the "acceptable" range for measurements. Our devices will send status updates periodically or in response to commands, as well as alerts for values outside the acceptable range. Since all the Publications in the domain will be encrypted, we use a pubValidator of AEADSGN and give the associated KMP capability *only* to collectors and we *require* that a collector have KMP capability. To indulge our paranoia (and for a faster sending path), we encrypt cAdd PDUs also, setting their validator to AEAD and requiring relay-capable identities to have KM capability in their signing chain while permitting collectors to have KM capability in their signing chains. Domain ruleset:

```
_dom: "meas"

#measPub: _domain/locId/type/typeArgs/msgID/sCnt/mts

collPub: #measPub & {
	locId: "mercury" | "venus" | "earth" | "mars" | "all"
	type:		"cmd" | "setRange"
} <= collSign

devPub: #measPub & {
	locId: _locId
	type:		"status" | "alert"
} <= devSign

signCert:	_dom/_locId/_role/_roleId/"sgn"/_keyinfo
idCert:		_dom/_locId/_role/_roleId/_keyinfo

collSign:	signCert & { _locId: "HQ", _role: "collect" } <= collCert
devSign:	signCert & { _locId:	"mercury" | "venus" | "earth" | "mars" } 
									 & { _role: "device" } <= devCert
rlySign: signCert & { _locId: ""mercury" | "venus" | "earth" | "mars"| "HQ" }
									& { _role: "connSrvr" | "connClnt" | "connMcst" } <= rlyCert
									 
collCert:	idCert <= kmpCap
devCert:	idCert <= domCert
rlyCert:	idCert <= rlyCap
domCert: _dom/_keyinfo

capCert:	_dom/"CAP"/capId/capArg/_keyinfo
kmCap:		capCert & { capId: "KM", capArg: _ } <= domCert
kmpCap:   capCert & { capId: "KMP", capArg: _ } <= kmCap | domCert
rlyCap: 	capCert & { capId: "RLY", capArg: _ } <= kmCap

#pubPrefix:    _dom
#pubValidator: "AEADSGN"
#wireValidator:"AEAD"

_keyinfo: "KEY"/_/"dct"/_
```

The Loc*Id*-Connector sync zones should only carry messages bound to or from Loc*Id*. We can specify this in a sub-schema if we constrain the locId name component for a legal Publication to be the same value as locId in the deftt's identity chain while also permitting "all" in a collPub. The sub-schema for the deftts of those sync zones is the same as above with the following modifications to Publication speciications where "my(*tag*)" is the value of *tag* in the local identity chain. (Recall that specifying "_*tag*" indicates the value of *tag* for the Publication signer's identity.) 

```
collPub: #measPub & {
	{ locTag: my(_locTag), type: "cmd" | "setRange"} |
	{ locTag: "all", type: "cmd" | "setRange"}
} <= collSign

devPub: #measPub & {
	locTag: my(_locTag)
	type:		"status" | "alert"
} <= devSign

```

The Loc*Id* subnet comprises devices and the EdgeLoc*Id* element. The requirement of measurement privacy indicates that two sync zones are needed on the subnet, one for the device Publications and one for the collector Publications. Then all the domain members in the subnet need a deftt in each sync zone, each with a different sub-schema. 

Picture of of Loc subnet indicating sync zone for collPubs and one for devPubs

The sub-schema for the Loc*Id*Coll sync zone is the same as the Loc*Id*-Connector sync zone but without the devPub definition. Devices will use a deftt with that schema for subscription only. EdgeLoc*Id* will have a deftt with that schema and will be the keymaker for the AEAD PDU encryption.

The sub-schema for the Loc*Id*Dev sync zone is the Loc*Id*-Connector schema without the collPub definition and with a PPAEAD PDU encryption. The EdgeLoc*Id*Dev deftt will be the keymaker and the only subscriber permitted in that sync zone. Since RLY deftts do not receive Publication encryption keys, EdgeLoc*Id*Dev will be able to decrypt the cAdd PDU but not the Publication it carries. Devices will not be able to decrypt each other's cAdd PDUs, so privacy is preserved. Relay identities are not shared outside of their sync zones, so the difference in the identity chain definition isn't a problem. (If there's a desire to use the same identity chain for all the deftts of EdgeLoc*Id*, the identity chain with the SG capability should be used in all rulesets.)

```
rlyCap: 	capCert & { capId: "RLY", capArg: _ } <= sgCap
sgCap:	capCert & { capId: "SG", capArg: _ } <= kmCap

#wireValidator: PPAEAD
```

