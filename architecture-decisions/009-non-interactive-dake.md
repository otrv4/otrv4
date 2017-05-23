## ADR 8: Non-interactive DAKE

### Context

OTRv3 only provides an interactive AKE and adding support to non-interactive
AKE is a usability feature.

A non-interactive DAKE starts by the receiver (R) requesting a pre-key for the
initiator (I) from a untrusted server. I's long-term public key must be known by R.

The receiver then generates their ephemeral keys and derives a shared secret
(and initial root and chain keys) which can be used to send an encrypted data
message together with his final message on the non-interactive DAKE.

The receiver can continue sending data messages even without receiving a reply
from the initiator, and forward secrecy is preserved by ratcheting the chain
key.

#### Publishing and retrieving prekeys to a prekey server

Implementers are expected to create their own policy dictating how often their
clients upload prekeys to the prekey server. This should be often enough to
minimize instances of prekeys running out on the server. Ideally, participation
deniability for the user is preserved in this process.

Interactions between OTRv4 clients and a prekey server are defined in a separate
specification.

#### Multiple clients

OTR uses instance tags to distinguish between different clients. This can be
solved by associating recipient long-term public keys with instance tags and
preventing multiple client to share the same long-term public key. A client
must distinguish between when a new long-term public key represents
a new device or the retirement of the previous key.

The client may receive multiple prekeys from a prekey server. The client must
decide how to reply to them. Each prekey may have a different client associated
with it and a different version.

#### Multiple OTR protocol versions

Prekeys contain:

```
Protocol version (SHORT)
Message type (BYTE)
Sender instance tag (INT)
User Profile (USER-PROF)
I (POINT) ECDH public key
B (MPI) DH public key
  Note: Although this is capital, this is not a point.
```

Each client is expected to upload one prekey per version of OTR after version 4
they support.

#### Handling multiple DAKEs for multiple settings

Currently we have decided on one state machine that accounts for multiple DAKEs.
The machine has the following states:
* Start
* Waiting for R Auth
* Waiting for I Auth
* Encrypted Message
* Finished

All of these states except the finished state may react to receiving the second
message of a non-interactive DAKE by validating it, destroying the current key
material and creating a new shared secret with the new message.

When Alice and Bob send each other the second message of the non-interactive
DAKE at the same time, both will need to decide which set of keys will be used
for their shared secret. Alice and Bob will use the same tie-breaking method
described in the interactive DAKE to choose.

#### What to do when the server runs out of prekeys

When the server runs out of prekeys, OTRv4 expects client implementations to
wait until a prekey is transmitted before continuing with a non-interactive
DAKE.

This is purposely different from what we expect from protocols like the Signal
Protocol. In Signal, when a prekey server runs out of prekeys, a default prekey
is used until new prekeys are uploaded. With this method, the consequences for
participation deniability are currently undefined, and we think this is risky.

By waiting for the server to send prekeys, OTRv4 will be subject to DoS
attacks when a server is compromised or the network is undermined to return a
"no prekey exists" response from the server. This is preferred over the possible
compromise of multiple non-interactive DAKEs due to the reuse of a prekey.
