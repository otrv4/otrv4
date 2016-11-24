# OTR version 4

This protocol provides a way for two people to have a conversation over a
network with the same security expectations as a private, in-person
conversation. No external party can overhear what is being said, and no
one (not even the participants) can prove what was said or that the two
participants spoke to each other at all. OTR works on top of an existing
messaging protocol, like XMPP.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)
2. [High Level Overview](#high-level-overview)
3. [Assumptions](#assumptions)
4. [Security Properties](#security-properties)
5. [Preliminaries](#preliminaries)
6. [OTR Conversation Initialization](#otr-conversation-initialization)
  1. [User Profile](#user-profile)
  2. [Creating a User Profile](#creating-a-user-profile)
  3. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
7. [Requesting conversation with older OTR version](#requesting-conversation-with-older-otr-version)
8. [Data exchange](#data-exchange)
9. [The protocol state machine](#the-protocol-state-machine)
10. [Socialist Millionaires' Protocol (SMP) version 2](#socialist-millionaires-protocol-smp-version-2)
11. [Appendices](#appendices)
  1. [ROM DRE](#rom-dre)
  2. [ROM Authentication](#rom-authentication)

## Main Changes over Version 3

- Improvements on security and privacy
  - Security level raised to 224 bits based on elliptic curve cryptography
  - Additional protection against transcript decryption in the case of
    elliptic curve cryptography compromise
- The cryptographic primitives and protocols have been updated.
  - Deniable Authenticated Key Exchange using SPAWN.
  - Key management using the Double Ratchet Algorithm.
- SMP
  - Upgraded the cryptographic primitives to use ECC based on the Edwards
    448 curve (Goldilocks).
  - Added new TLVs to keep compatibility for the previous SMP protocol. (TODO: WAT WAT WAT)


## High Level Overview

The high level flow of the protocol looks like this:

    Alice                                            Bob
    --------------------------------------------------------------------------------
    Request OTR conversation          ------------->
    Establish Conversation with DAKE  <------------>  Establish Conversation with DAKE
    Exchange Data Messages            <------------>  Exchange Data Messages

The initial step to request an OTR conversation is optional and will not always be present.

## Assumptions

Both participants are online at the start of a conversation.

Messages in a conversation can be exchanged over an insecure channel, where an
attacker can eavesdrop or interfere with the encrypted messages.

We assume a network model which provides in-order delivery of messages, but some
messages may not be delivered.

## Security Properties

In an OTRv4 conversation, both sides can verify the identity of the
other participant but cannot transfer this knowledge to a third party.

Once an OTRv4 channel has been created, all messages transmitted through this
channel are confidential and integrity protected.

Both parties can deny that they have participated in a conversation. They can
also deny having sent any of the exchanged messages in the conversation. The
respective party can be certain of the authenticity of the messages but cannot
transfer this knowledge to someone else.

On the other hand, OTRv4 does not protect against an active attacker performing
Denial of Service attacks to reduce availability.

## Notation and parameters

This section contains information needed to understand the parameters and
arithmetic used.

### Notation

Scalars are in lower case, such as `x` or `y`. Points and other variables are in
upper case, such as `P` or `Q`.

Addition and subtraction of elliptic curve points `A` and `B` are `A + B` and `A - B`.
Addition of a point to another point generates a third point. Scalar
multiplication with a scalar `a` with an elliptic curve point `B` yields a
new point: `C = a * B`.

The concatenation of byte sequences `I` and `J` is `I || J`. In this case, `I` and `J`
represent a fixed-length byte sequence encoding the respective values. See
section [Data types](#data-types) for encoding and decoding details.

### Elliptic Curve Parameters

OTRv4 uses the [Ed448-Goldilocks][4] [elliptic curve][5], which defines the
following parameters:

```
Base point (B)
  (x=11781216126343694673728248434331006466518053535701637341687908214793
     9404277809514858788439644911793978499419995990477371552926308078495,
   y=19)

Cofactor (c)
  4

Identity point (I)
  (x=0,
   y=1)

Field prime (p)
  2^448 - 2^224 - 1

Order of base point (q) [prime; q < p; q*B = I]
  2^446 - 13818066809895115352007386748515426880336692474882178609894547503885

Number of bits in p (|p|)
  448 bits

Number of bits in q (|q|)
  446 bits
```

A scalar modulo `p` is a "field element", and should be encoded and decoded
using the rules for MPIs.

### 3072 Diffie-Hellman Parameters

For the Diffie-Hellman group computations, the group is the one defined in [RFC
3526][1] with a 3072-bit modulus (hex, big-endian):

```
Prime: 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }

Value:
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF

Generator g3: 2
```

Note that this means that whenever you see an operation on a field element from
the above group, the operation should also be done module the above prime.


### TLV Types

(TODO: this paragraph should not be here)
OTRv4 has the same message formats as OTRv3 without compatibility with version 2.
This means that query messages, whitespace tags, error messages, encoding and
fragmentation is performed as specified in OTRv3.

(TODO: this paragraph should not be here)
The fragmentation format is the same as for OTRv3. You will have to wait until
after reassembly to finalize how to deal with a message. For details, see
[fragmentation section][3] in OTRv3 documentation.

Although Data Messages have a different format in OTRv4, they use the same
format for TLV (type/length/value) records. OTRv4 supports the same TLV record
types from OTRv3, with the exception of SMP (version 1) TLVs (types 2-7).

OTRv4 defines additional TLV record types:

* Type 10: SMP Abort Message
  If the user cancels SMP prematurely or encounters an error in the protocol and
  cannot continue, you may send a message (possibly with empty human-readable
  part) with this TLV type to instruct the other party's client to abort the
  protocol. The associated length should be zero and the associated value should
  be empty. If you receive a TLV of this type, you should change the SMP state
  to SMPSTATE_EXPECT1 (see below).

* Type 11: SMPv2 Message 1
  The value represents an initiating message of the Socialist Millionaires'
  Protocol, described below.

* Type 12: SMPv2 Message 2
  The value represents the second message in an instance of SMPv2.

* Type 13: SMPv2 Message 3
  The value represents the third message in an instance of SMPv2.

* Type 14: SMPv2 Message 4
  The value represents the final message in an instance of SMPv2.

* Type 15: SMPv2 Message 1Q
  Like a SMPv2 Message 1, but whose value begins with a NUL-terminated
  user-specified question.

### Data types

OTRv4 uses almost the same data types as specified in OTRv3 (bytes, shorts, ints, MPIs,
and DATA) except for CTR and MAC, and with the addition of:

```
Nonce (NONCE):
  24 byte (192-bit) one time use nonce for XSalsa20 encryption  (TODO: this is incsonsistent, and doesn't describe that it's a byte array)

ED448 point (POINT):
  56 byte unsigned value, big-endian
```

### DRE messages and Auth NIZKPK

A dual-receiver encrypted message is serialized as follows:

```
Dual-receiver encrypted message (DRE-M):

  U11 (POINT)
  U21 (POINT)
  E1 (POINT)
  V1 (POINT)
  U12 (POINT)
  U22 (POINT)
  E2 (POINT)
  V2 (POINT)
  l (MPI)
  n1 (MPI)
  n2 (MPI)
  nonce (NONCE)
  φ (DATA)
    Where (U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, φ) = DREnc(pubA, pubB, m)
```

An Auth non-interactive zero-knowledge proof of knowledge is serialized as
follows:

```
Auth message (AUTH):

  c1 (MPI)
  r1 (MPI)
  c2 (MPI)
  r2 (MPI)
  c3 (MPI)
  r3 (MPI)
    Where (c1, r1, c2, r2, c3, r3) = Auth(A_2, a_2, {A_1, A_3}, m)
```

### Public keys and fingerprints

OTRv4 introduces a new type of public-key:

(TODO: these parameters should all be upper case)

```
OTR public authentication Cramer-Shoup key (CRAMER-SHOUP-PUBKEY):

    Pubkey type (SHORT)
      Cramer-Shoup public keys have type 0x0010

    c (MPI)
    d (MPI)
    h (MPI)
      (c, d, h) are the Cramer-Shoup public key parameters
```

OTR public keys have fingerprints, which are hex strings that serve as
identifiers for the public key. The fingerprint is calculated by taking the
SHA3-256 hash of the byte-level representation of the public key.


## Key management

In the DAKE, OTRv4 makes use of long-term Cramer-Shoup keys and ephemeral D-H
keys.

For exchanging data messages, OTRv4 uses a key structure and
key rotation strategy inspired by the [Double Ratchet] algorithm [6]. The goal is to
provide forward secrecy even in the event of not receiving messages from the
other participant for a considerable amount of time.

The messages are encrypted and authenticated using a set of receiving and
sending MAC and encryption keys, derived from the sending and receiving chain
keys.

OTRv4 keys are rotated in three different levels:

1. Root level: every time a new D-H key is advertised/acknowledged a new root
   key is derived, as long as new initial sending and receiving chain keys.
(TODO: I have no idea what this sentence means)


2. Chain level: every time a new message needs to be sent before an
   acknowledgement is received, the sending chain key is rotated, being derived
   from the previous sending chain key.
(TODO: the acknowledgment part in the middle here is quite confusing)


3. Mix key level: every third time a party has gone through three root level
   level rotations, the mix key is rotated and the resulting DH public
   key should be adevertised / acknowledged.
(TODO: this one is very confusing too)


In order to manage keys, each correspondent keeps track of:

(TODO: the below should be consistent with our naming conventions, uppercase/lowercase)
(TODO: we probably need to defined the word ratchet somewhere, or at least how it's used here)
```
State variables:
  initiator: the participant who should perform the first root key rotation after the DAKE completes.
  i: the current ratchet id.
  j: the last sent message id
  k: the last received message id.

Key variables:
  R[i]: the Root key for the ratchet i.
  Cs[i][j]: the sending chain key for the message j in the ratchet i.
  Cr[i][k]: the receiving chain key for the message k in the ratchet i.
  our_previous_ecdh: our previous ECDH ephemeral key pair.
  our_ecdh: our current ECDH ephemeral key pair.
  their_ecdh: their ECDH ephemeral public key.
  our_dh: our DH ephemeral key pair
  their_dh: their DH ephemeral public key
  dh_shared_secret: the shared secret previously computed.
  macs_to_reveal: MAC keys pending to be revealed.
```

The previously mentioned variables are affected by these events:

* When you send a DAKE message (starting a new DAKE).
* Upon completing the DAKE.
* When you send a Data Message.
* When you receive a Data Message.
(TODO: what about other messages? End conversation messages for example?)

### Calculating Keys

This section describes the functions used to manage the key material.


(TODO: what happens if you ratchet without sending any messages? Are we deleting key material we need?)
#### Ratcheting the ECDH keys

The participant invoking this is moving into a new ECDH ratchet. The next data
message will advertise a new ratchet (`i + 1`) from the receiver perspective.

When you ratchet the ECDH keys, you:

* Securely delete `our_ecdh`.
* Generate a new ECDH key pair and assign it to `our_ecdh`. See [newECDH()](#ECDH-and-DH-Shared-Secrets).
* Increment the current ratchet ID `i = i +1`.
* Reset the last sent message ID `j = 0`.

(TODO: what happens if you ratchet without sending any messages? Are we deleting key material we need?)
#### Ratcheting the DH keys

The rotation of the DH keys does not happen every ratchet but
every third.

If `i` is bigger than zero and a multiple of three:

  * Securely delete `our_dh`.
  * Generate a new DH key pair and assign it to `our_dh`. See [newDH()](#ECDH-and-DH-Shared-Secrets).
  * Calculate a new `dh_shared_secret = SHA3-256(DH(our_dh.secret, their_dh))`.

Otherwise:

  * Derive a new `dh_shared_secret = SHA3-256(dh_shared_secret)`.

#### ECDH and DH Shared Secrets

```
pubECDH, secretECDH = newECDH()

ecdh_shared_secret = (G1*x)*y (POINT)
  The shared ECDH key.

dh_shared_secret = (g3^x)^y mod p (MPI)
  The shared 3072-bit DH key.
```

#### Mixed Secret: Mixing ECDH and DH Shared Secrets
(TODO: this is using mix_key instead of dh_shared_secret)
```
calculate_shared_secret(ecdh_shared_secret, mix_key):
   serialized_EC_secret = serialize_point(ecdh_shared_secret)
   serialized_mix_key = serialize_MPI(mix_key)
   return SHA3-512(serialized_EC_secret, serialized_mix_key)
```

#### Calculate Double Ratchet Keys

```
calculate_ratchet_keys(secret):
  R  = SHA3-512(0x01 || secret)
  Ca = SHA3-512(0x02 || secret)
  Cb = SHA3-512(0x03 || secret)
  return R, decide_between_chain_keys(Ca, Cb)
```

#### Decide Between Chain Keys
(TODO: this uses the "initiator" flag which shouldn't exist anymore)
Both sides will compare their public keys to choose a chain key for sending and receiving:
- Alice (and similarly for Bob) determines if she is the "low" end or the "high" end of this ratchet.
If Alice's ephemeral D-H public key is numerically greater than Bob's public key, then she is the "high" end.
Otherwise, she is the "low" end.
- Alice selects the chain keys for sending and receiving:
  - If she is the "high" end, set `initiator` as `true`, use Ca as the sending chain key (Cs), Cb as the receiving chain key (Cr).
  - If she is the "low" end, set `initiator` as `false`, use Cb as the sending chain key (Cs), Ca as the receiving chain key (Cr).

TODO: we can not set the initiator as a side effect of deciding who will use each key, but we can use the same condition to decide who will be initiator. This may be a problem because every time I talk to Bob I will have the same condition.

### Deriving new chain keys

When you send or receive data messages you need to derive a new chain key:
(TODO: this doesn't take into account the first time, when the chain key is derived from the ratchet key. We might need to define it for those circumstances)
```
derive_chain_key(C, i, j):
  C[i][j] = SHA3-512(C[i][j-1])
```

### Calculate Encryption and MAC keys

When you send or receive data messages you need to calculate the message keys:

```
calculate_encryption_and_mac_keys(chain_key):
  enc = SHA3-256(0x00 || chain_key)
  mac = SHA3-512(0x01 || chain_key)
  return enc, mac
```


### Recovering past chain keys

When receiving a data message, you may need to use receiving chain
keys where the message id is older than `j - 1` to calculate the
current if you did not receive previous messages. For example, your
peer sends you data messages with ids `j = 1, j = 2, j = 3`, but you only
receive messages with ids `j = 1, j = 3`. In that case you would use the
chain key for message id `j = 1` to derive the chain key for message
`j = 3`.
(TODO: this loop doesn't update k)
```
recover_receiving_chain_keys(i, j, k):
  do
    derive_chain_key(Cr, i, k)
  while(k <= j)
```


## Conversation Initialization

OTRv4 will initialize athrough a Query message or a whitespace tag, as discussed
in OTRv3 [3]. After this, the conversation is authenticated using a deniable
authenticated key exchange (DAKE). The conversation can also be started directly
with the first message of the DAKE, without a Query message or a whitespace tag.

### Requesting conversation with older OTR versions

Bob might respond to Alice's request or notification of willingness to start a
conversation using OTRv3. If this is the case and Alice supports the version 3,
the protocol falls back to OTRv3 [3].
(TODO: what happens otherwise?)


## User Profile

OTRv4 introduces mandatory user profile publication. The user profile contains the
Cramer-Shoup long term public key, signed version support information, and a signed
profile expiration date. Both parties will include the user profile in the beginning
of the DAKE. The frequency of the user profile publication is determined by its
expiration and renewal policy.

(TODO: IT HAS to be published in a public space as well)


### Creating an User Profile

(TODO: why is Bob necessary here? The user profile creation doesn't happen during a conversation, right?)

To create a user profile, both Alice and Bob generate:

1. The Cramer-Shoup key-pair: PK, SK
2. Version support information string in the same format as OTRv3 Query Messages [3]
3. Profile Expiration  (TODO: what format?)
4. (optional) Transition signatures are signatures of the DSA fingerprints related
   to the keys used for version 3. This is only used if the user supports
   version 3 and 4.
(TODO: this is incorrect, it's supposed to be a signature generated USING the DSA key, of the new cramer shoup fingerprint)


One of the Cramer-Shoup secret key values (`z`) and its generator (`g1`) is used to create
signatures of the entire profile. This is created using the Ed448 signature algorithm as
documented in [4].

The user profile components are as follows:

1. PK
2. version_info
3. profile_expiration
4. profile_sig = sign( PK, version_info, profile_expiration )
5. (optional) fingerprints
6. (optional) fingerprint_sig = sign( otrv3_DSA_fingerprint ) (1 per fingerprint)
(TODO: why have this both here and in the data type below?)

Then this profile should be published in a public place, like an untrusted
server.

#### Renewing a Profile

If a renewed profile is not published and if the only publicly available profile
is expired, this puts the user's participation deniability at risk.

Before the profile expires, the user must publish an updated profile with a new
expiration date. The client establishes the frequency of expiration - this can
be configurable. A recommended value is two weeks.

#### User Profile Data Type

```
User Profile (USER-PROF):
  Cramer-Shoup key (CRAMER-SHOUP-PUBKEY)
  Version (VER)
  Version Expiration (VER-EXP)
  Signature of profile (SIG)
  Transitional Fingerprints (TRANSITION-FP)

Version (VER):
  A string corresponding to the user's supported OTR versions. The format is
  described in OTR version 3 under the section "OTR Query Messages".
  (TODO: this needs to have some length encoding or something)

Version Expiration (VER-EXP):
  4 byte value that contains the date that this profile will expire.
  (TODO: this needs to be specified)

Signature of profile (MPI):

Transitional Fingerprints (TRANSITION-FP)
  1 byte unsigned number of fingerprints, big-endian
  20 byte (160 bits) unsigned fingerprint, big-endian for each
  112 byte (896 bits) unsigned signature, big-endian for each
(TODO: the above is incorrect, since the transitional fingerprint was misunderstood)
```

### Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the Deniable Authenticated Key Exchange, which
is a way for two parties to mutually agree upon a shared key and authenticate
one another while also providing participation deniability.

This protocol is derived from the [Spawn protocol][2], which uses dual-receiver
encryption (DRE) and a non-interactive zero-knowledge proof of knowledge
(NIZKPK) for authentication (Auth).

Alice long-term Cramer-Shoup key-pair is `SKa = (x1a, x2a, y1a, y2a, za)` and
`PKa = (Ca, Da, Ha)`. Bob long-term Cramer-Shoup key-pair is `SKb = (x1b, x2b,
y1b, y2b, zb)` and `PKb = (Cb, Db, Hb)`. Both key pairs are generated with
`DRGen()`.

(TODO: it might be useful to specify that the DH and ECDH keys are ephemeral)
#### Overview

```
a, b: DH secret key
A, B: DH public key
K_dh: mix-key, a shared secret computed from a DH exchange = A^b, B^a

x, y: ECDH secret key
X, Y: ECDH public key = G1*x, G1*y
K_ecdh: a shared secret computed from an ECDH exchange = X*y, Y*x
```

```
Alice (I)                                Bob (R)
---------------------------------------------------
Query Message or Whitespace Tag ------->
                                <------- Prekey (ψ1)
                  DRE-Auth (ψ2) ------->
                                         Verify & Decrypt (ψ2)
```

Bob will be initiating the DAKE with Alice.

**Bob:**

1. Generates an ephemeral ECDH secret key `y` and a public key `Y`.
2. Generates an ephemeral DH secret key `b` and a public key `B`.
3. Sends Alice a pre-key message `ψ1 = ("Prof_B", Y, B)`. Prof_B is
   Bob's User Profile.


**Alice:**

1. Generates an ephemeral ECDH secret key `x` and a public key `X`.
2. Generates an ephemeral DH secret key `a` and a public key `A`.
3. Computes `γ = DREnc(PKa, PKb, m)`, being `m = "Prof_B" || "Prof_A" || Y || X || B || A`.
   Prof_A is Alice's User Profile.
4. Computes `σ = Auth(Ha, za, {Hb, Y}, "Prof_B" || "Prof_A" || Y || B || γ)`.
5. Computes root level keys (`R`, `Cs`, and `Cr`).
6. Sends Alice a DRE-Auth Message `ψ2 = ("R", γ, σ)`.

**Bob:**
(TODO: I still hate "Verif")
1. Verifies `Verif({Hb, Ha, Y}, σ, “Prof_B” || “Prof_A” || Y || B || γ)`.
2. Decrypts `m = DRDec(PKb, PKa, SKb, γ)`.
3. Verifies the following properties of the decrypted message `m`:
  1. The message is of the correct form (e.g., the fields are of the expected length)
  2. Alice's identifier is the first one listed
  3. Bob's identifier is the second one listed, and it matches the identifier
     transmitted outside of the ciphertext
  4. `(Y, B)` is a prekey that Bob previously sent and remains unused.
4. Computes root level keys (`R`, `Cs`, and `Cr`).

(TODO: what happens if any of the verifications fails?)

#### When you start a new DAKE

(TODO: what is different here, compared to these descriptions in the previous section?)
The DAKE is considered to start when either:

1. Bob sends the pre-key message. In this case:
  * Generate a new ephemeral ECDH key pair `(y, Y)`.
  * Generate a new ephemeral 3072-bit DH key pair: `(b, B)`.
  * Set `prev_our_ecdh` as your current ECDH key pair (`our_ecdh`), if you have it.
  * Set `our_ecdh` as our ECDH ephemeral key pair from the DAKE (`(y, Y)`).
  * Set `our_dh` as our DH ephemeral key pair from the DAKE (`b`, `B`).
  * Set `j = 1` because the pre-key message is considered the first in this DH ratchet.
  * Increase ratchet id `i = i + 1`.


2. Alice receives the pre-key message. In this case:
  * Generate a new ephemeral ECDH key pair `(x, X)`.
  * Generate a new ephemeral 3072-bit DH key pair: `(a, A)`.
  * Set `prev_our_ecdh` as your current ECDH key pair (`our_ecdh`), if you have it.
  * Set `our_ecdh` as our ECDH ephemeral key pair from the DAKE (`(x, X)`).
  * Set `our_dh` as our DH ephemeral key pair from the DAKE (`a`, `A`).
  * Set `their_ecdh` as their ECDH ephemeral public key from the DAKE (`Y`).
  * Set `their_dh` as their DH ephemeral public key from the DAKE (`B`).
  * Increase ratchet id `i = i + 1`.
  * Reply with a DRE-Auth message.


#### After you complete the DAKE

The DAKE is considered to be completed when either:

1. Alice sends the DRE-Auth message. In this case:
  * Set `j = 0` to cause a DH-ratchet the next time a msg is sent.
  * Increase ratchet id `i = i + 1`.

2. Bob receives and verifies the DRE-Auth message. In this case:
  * Set `their_ecdh` as their ECDH ephemeral public key from the DAKE (`X`).
  * Set `their_dh` as their DH ephemeral public key from the DAKE (`A`).
  * Increase ratchet id `i = i + 1`.

Regardless of who you are:

* Calculate `K_ecdh` and `K_dh`. TODO: is this our_* or K_*.
* Securely erase `our_ecdh.private` and `our_dh` key pair.
* Calculate `K = calculate_shared_secret(K_ecdh, K_dh)`.
* Calculate the SSID from shared secret: let SSID be the first 64 bits of `SHA3-256(0x00 || K)`.
* Calculate the first set of keys with `R[i], Cs[i][0], Cr[i][0] = calculate_ratchet_keys(K)`.


#### Pre-key message

This is the first message of the DAKE. Bob sends it to Alice to commit to a
choice of D-H and ECDH key. A valid Pre-key message is generated as follows:

1. Create a user profile. How to do this is detailed [here](#creating-a-user-profile)
2. Choose a random ephemeral ECDH key pair:
  * secret key `x` a random element from `Z_q` (448 bits).
  * public key `X`
3. Generates an ephemeral D-H secret key pair:
  * secret key `a` (640 bits).
  * and a public key `A = g3 ^ a`.

A pre-key is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x01.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For a pre-key message this will often be 0,
  since the other party may not have identified their instance tag yet.
Sender's User Profile (USER-PROF)
  This is described in the section 'Creating a User Profile'.
X (POINT)
  The ephemeral public ECDH key.
A (MPI)
  The ephemeral public D-H key.
```

#### DRE-Auth message

This is the second message of the DAKE. Alice sends it to Bob to commit to a
choice of her D-H key and acknowledgement of Bob's D-H key. The long-term public
key and D-H public keys are encrypted with DRE and authenticated with an NIZKPK.

A valid DRE-Auth message is generated as follows:

1. Create a user profile. How to do this is detailed [here]
   (#creating-a-user-profile)
2. Choose a random ephemeral ECDH key pair:
  * secret key `y` a random element from `Z_q` (448 bits).
  * public key `Y`
3. Generates an ephemeral D-H secret key pair:
  * secret key `b` (640 bits).
  * and a public key `B = g3 ^ b`.
4. Generate `m = X || Y || A || B`
5. Compute `DREnc(pubA, pubB, m)` and serialize it as a DRE-M value in the variable `γ`.
6. Compute `σ = Auth(Hb, zb, {Ha, X}, "Prof_B" || "Prof_A" || X || A || γ)`.


A DRE-Auth is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x02.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient.
Receiver's User Profile (USER-PROF)
  This is described in the section 'Creating a User Profile'.
γ (DRE-M)
  The Dual-receiver encrypted value.
σ (AUTH)
  The Auth value.
```


## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange data initialized with the shared secret established in the
DAKE.

A message with an empty human-readable part (the plaintext is of zero length, or
starts with a NUL) is a "heartbeat" packet, and should not be displayed to the
user. (But it's still useful to effect key rotations.)

```
Alice                                                                           Bob
-----------------------------------------------------------------------------------
Initialize root key, chain keys                        Initialize root key, chain keys
Generate K_ecdh, X, x                                  Generate K_ecdh, Y, y
Generate K_dh, A, a                                    Generate K_dh, B, b
Send data message 0_0            -------------------->
Send data message 0_1            -------------------->

                                                       Receive data message 0_0
                                                       Recover receiving chain key 0_0
                                                       Derive Enc-key & MAC-key
                                                       Verify MAC, Decrypt message 0_0

                                                       Receive data message 0_1
                                                       Recover receiving chain key 1_1
                                                       Derive Enc-key & MAC-key
                                                       Verify MAC, Decrypt message 0_1

                                                       Perform a new ratchet
                                 <-------------------- Send data message 1_0
                                 <-------------------- Send data message 1_1

Receive data message 1_0
Recover receiving chain key 1_0
Derive Enc-key & MAC-key
Verify MAC, Decrypt message 1_0

Receive data message 1_1
Recover receiving chain key 1_1
Derive Enc-key & MAC-key
Verify MAC, Decrypt message 1_1
```

#### When you send a Data Message:

In order to send a data message a key to encrypt the message is
required. This key will be derived from a previous chain key and if
the message's counter `j` has been reset to zero keys should be
rotated. Also this derivation takes into account a DH key, referred to
as a mix key, which is rotated every third ratchet.

Given a new ratchet begins and either this ratchet is not the first or
you are the initiator:

  * Ratchet the ECDH keys. See "Ratcheting the ECDH keys" section.
  * Ratchet the DH keys. See "Ratcheting the DH keys" section.
  * Derive new set of keys `R[i], Cs[i][j], Cr[i][j]`.
  * Securely delete the root key and all chain keys from the ratchet `i-2`.

  ```
  mixed = ECDH(our_ecdh.secret, their_ecdh) || dh_shared_secret
  R[i], Cs[i][j], Cr[i][j] = calculate_ratchet_keys(R[i-1] || mixed)
  delete(R[i-2])
  delete(Cs[i-2])
  delete(Cr[i-2])
  ```

Otherwise:

  * Increment last sent message ID `j = j+1`.
  * Derive the next sending Chain Key `derive_chain_key(Cs, i, j)`.
  * Securely delete `Cs[i][j-1]`.

In any event:

1. Calculate the encryption key (`MKenc`) and the mac key (`MKmac`):

   ```
   MKenc, MKmac = calculate_encryption_and_mac_keys(Cs[i][j])
   ```

2. Use the encryption key to encrypt the message, and the mac key to calculate its MAC:

   ```
   Nonce = generateNonce()
   Encrypted_message = XSalsa20_Enc(MKenc, Nonce, m)
   Authenticator = SHA3-512(MKmac || Encrypted_message)
   ```

3. Forget and reveal MAC keys. The conditions for revealing MAC keys is in the
   "Revealing MAC keys" section.


#### When you receive a Data Message:

Reject messages with `ratchet_id` less than the `i-1` or greater than `i+1`.
Reject messages with `message_id` less than the `k`. This is to enforce rejecting messages
delivered out of order.

TODO: Why do we reject messages with ratchet_id < i-1 if we dont do anything with
messages with ratchet_id i-1? Now, we should do (for allowing receiving messages)
from the previous session when a new DAKE has just finished.

TODO: We need to be able to decrypt messages from the previous ratchet (yesterday's discussion).

Use the message `ID` to compute the receiving chain key and calculate encryption and mac keys.

```
TODO: Why this code always uses the current ratchet_id and totally ignores the
ratchet_id from the message?
//k = is the last received message id
recover_receiving_chain_keys(i, k, message_id)
MKenc, MKmac = calculate_encryption_and_mac_keys(Cr, i, message_id)
```

Use the "mac key" (`MKmac`) to verify the MAC on the message.

If the message verification fails, reject the message.

Otherwise:

  * Decrypt the message using the "encryption key" (`MKenc`) and securely delete MKenc.
  * Securely delete receiving chain keys older than `message_id-1`.
  * Set `j = 0` to indicate a new DH-ratchet should happen next time you send a message.
  * Set `their_ecdh` as the "Next Public ECDH key" from the message.
  * Set `their_dh` as the "Next Public DH Key" from the message, if it
    is not NULL.
  * Add the MKmac key to list of pending MAC keys to be revealed.


### Revealing MAC Keys

We reveal old MAC keys to provide forgeability of messages. Old MAC keys are
keys for messages that have already been received, therefore will no longer be
used to verify the authenticity of a message.

MAC keys are revealed with data messages. They are also revealed with heartbeat
messages (data messages that encode a plaintext of zero length) if the receiver
has not sent a message in a configurable amount of time. Put them (as a set
of concatenated 20-byte values) into the "Old MAC keys to be revealed"
section of the next Data Message you send. 

A receiver can reveal a MAC key in the following case:

- the receiver has received a message and has verified the message's authenticity
- the receiver has discarded associated message keys


### Data Message format

```
Protocol version (SHORT)

    The version number of this protocol is 0x0004.

Message type (BYTE)

    The Data Message has type 0x03.

Sender Instance tag (INT)

    The instance tag of the person sending this message.

Receiver Instance tag (INT)

    The instance tag of the intended recipient.

Flags (BYTE)

    The bitwise-OR of the flags for this message. Usually you should
    set this to 0x00. The only currently defined flag is:

    IGNORE_UNREADABLE (0x01)

        If you receive a Data Message with this flag set, and you are
        unable to decrypt the message or verify the MAC (because, for
        example, you don't have the right keys), just ignore the message
        instead of producing some kind of error or notification to the user.

Ratchet id ratchet_id (INT)

    Must be strictly greater than 0, and increment by 1 with each ratchet.
    This should receive the value of i variable.

Message id message_id (INT)

    Must be strictly greater than 0, and increment by 1 with each message.
    This should receive the value of j variable.

Next Public ECDH Key (POINT)

    The sender's current ratchet ECDH public key for the sender.
    This should receive the value of our_ecdh.public_key variable.

Next Public DH Key (MPI)

    This should receive the value of our_dh.public_key variable.
    You should send a NULL value if i % 3 != 0.

Nonce (NONCE)

    The nonce used with XSalsa20 to create the encrypted message contained in
    this packet.

Encrypted message (DATA)

    Using the appropriate encryption key (see below) derived from the
    sender's and recipient's DH public keys (with the keyids given in this
    message), perform XSalsa20 encryption of the message. The nonce used for
    this operation is also included in the header of the data message packet.

Authenticator (MAC)

    The SHA3 MAC, using the appropriate MAC key (see below) of everything
    from the Protocol version to the end of the encrypted message.

Old MAC keys to be revealed (DATA)

    See "Revealing MAC Keys"
```


## The protocol state machine

An OTR client maintains separate state for every correspondent. For example,
Alice may have an active OTR conversation with Bob, while having an unprotected
conversation with Charlie. This state consists of two main state variables, as
well as some other information (such as encryption keys). The two main state
variables are:

### Message state

The message state variable, `msgstate`, controls what happens to outgoing messages
typed by the user. It can take one of three values:

```
MSGSTATE_PLAINTEXT
    This state indicates that outgoing messages are sent without encryption.
    This is the state that is used before an OTR conversation is initiated.
    This is the initial state, and the only way to subsequently enter this
    state is for the user to explicitly request to do so via a UI
    operation.

MSGSTATE_ENCRYPTED
    This state indicates that outgoing messages are sent encrypted.
    This is the state that is used during an OTR conversation. The only way
    to enter this state is for the authentication state machine (below) to
    successfully complete.

MSGSTATE_FINISHED
    This state indicates that outgoing messages are not delivered at all.
    This state is entered only when the other party indicates he has
    terminated his side of the OTR conversation. For example, if Alice and
    Bob are having an OTR conversation, and Bob instructs his OTR client to
    end its private session with Alice (for example, by logging out), Alice
    will be notified of this, and her client will switch to MSGSTATE_FINISHED
    mode. This prevents Alice from accidentally sending a message to Bob in
    plaintext. (Consider what happens if Alice was in the middle of typing a
    private message to Bob when he suddenly logs out, just as Alice hits
    Enter.)
```


### Authentication state

The authentication state variable, `authstate`, can take one of four values:

```
AUTHSTATE_NONE
    This state indicates that the authentication protocol is not currently in
    progress. This is the initial state.

AUTHSTATE_AWAITING_DRE_AUTH

    After Bob initiates the authentication protocol by sending Alice the Pre-
    key Message, he enters this state to await Alice's reply.
```


### Policies

OTR clients can set different policies for different correspondents. For
example, Alice could set up her client so that it speaks only OTR version 4,
except with Charlie, who she knows has only an old client; so that it will
opportunistically start an OTR conversation whenever it detects the
correspondent supports it; or so that it refuses to send non-encrypted messages to Bob, ever.

The policies that can be set (on a global or per-correspondent basis) are any
combination of the following boolean flags:

```
ALLOW_V3
  Allow version 3 of the OTR protocol to be used.

ALLOW_V4
  Allow version 4 of the OTR protocol to be used.

REQUIRE_ENCRYPTION
  Refuse to send unencrypted messages.

SEND_WHITESPACE_TAG
  Advertise your support of OTR using the whitespace tag.

WHITESPACE_START_DAKE
  Start the OTR DAKE when you receive a whitespace tag.

ERROR_START_DAKE
  Start the OTR DAKE when you receive an OTR Error Message.
```

Note that it is possible for UIs simply to offer the old "combinations" of
options, and not ask about each one separately.


### State transitions

There are ten actions an OTRv4 client must handle:

User actions:
  * User requests to start an OTR conversation
  * User requests to end an OTR conversation
  * User types a message to be sent

Received messages:
  * Plaintext without the whitespace tag
  * Plaintext with the whitespace tag
  * Query Message
  * Error Message
  * Pre-key message
  * DRE-Auth message
  * Data Message


The following sections will outline what actions to take in each case. They all
assume that at least one of `ALLOW_V3` or `ALLOW_V4` is set; if not, then OTR is
completely disabled, and no special handling of messages should be done at all.
Version 1 and 2 messages are out of the scope of this specification.

For version 3 and 4 messages, someone receiving a message with a recipient
instance tag specified that does not equal their own should discard the message
and optionally warn the user. The exception here is the D-H Commit Message where
the recipient instance tag may be 0, indicating that no particular instance is
specified.


#### User requests to start an OTR conversation

Send an OTR Query Message to the correspondent.


#### Receiving plaintext without the whitespace tag

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * Simply display the message to the user.
  * If `REQUIRE_ENCRYPTION` is set, warn him that the message was received unencrypted.

If `msgstate` is `MSGSTATE_ENCRYPTED` or `MSGSTATE_FINISHED`:

  * Display the message to the user, but warn him that the message was received unencrypted.


#### Receiving plaintext with the whitespace tag

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * Remove the whitespace tag and display the message to the user.
  * If `REQUIRE_ENCRYPTION` is set, warn him that the message was received unencrypted.

If `msgstate` is `MSGSTATE_ENCRYPTED` or `MSGSTATE_FINISHED`:

  * Remove the whitespace tag and display the message to the user.
  * Warn him that the message was received unencrypted.

In any event, if `WHITESPACE_START_DAKE` is set:

If the tag offers OTR version 4 and `ALLOW_V4` is set:

  * Send a version Pre-key Message.
  * Transition `authstate` to `AUTHSTATE_AWAITING_DRE_AUTH`.

If the tag offers OTR version 3 and `ALLOW_V3` is set:

  * Send a version 3 D-H Commit Message
  * Transition `authstate` to `AUTHSTATE_AWAITING_DHKEY`.
  * The protocol proceeds as specified in OTRv3.


#### Receiving a Query Message

If the query message offers OTR version 4 and `ALLOW_V4` is set:

  * Send a Pre-key Message
  * Transition `authstate` to `AUTHSTATE_AWAITING_DRE_AUTH`.

Otherwise, if the query message offers OTR version 3 and `ALLOW_V3` is set:

  * Send a version 3 D-H Commit Message.
  * Transition `authstate` to `AUTHSTATE_AWAITING_DHKEY`.
  * The protocol proceeds as specified in OTRv3.


#### Receiving an Error Message

  * Display the message to the user.
  * If `ERROR_START_DAKE` is set, reply with a Query Message.
  * TODO: Should all state machines be reset?
  * TODO: Should `authstate` and `msgstate` be reset?


#### Receiving a Pre-key message

If the message is version 4 and `ALLOW_V4` is not set, ignore this message. Otherwise:

If `authstate` is `AUTHSTATE_AWAITING_DRE_AUTH`:

This indicates that you have already sent a Pre-key message to your
correspondent, but that she either didn't receive it, or just didn't receive it
yet, and has sent you one as well.

The symmetry will be broken by comparing the hashed `X` you sent in your pre-key
message with the one you received, considered as X-byte unsigned big-endian
values.

If yours is the lower hash value:
  * Ignore the incoming pre-key message.
    (TODO: OTRv3 would resend your pre-key message in this case. Should we?)

Otherwise:
  * Forget your old `X` value that you sent earlier, and pretend you're in
     `AUTHSTATE_NONE`; i.e. generate a new `y` and `Y` values.

Regardless of `authstate` value, if you haven't ignored the incoming pre-key
message, you should:

  * Verify that the profile signature is valid.
  * Verify that the profile is not expired.
  * Verify that the point X received in the pre-key message is on curve 448.
  * Verify that the D-H public key is from the correct group.

If everything checks out:

  * Reply with a DRE-Auth Message.
  * Compute the ECDH shared secret `K_ecdh = (G1*x)*y`.
  * Transition `authstate` to `AUTHSTATE_NONE`.
  * Transition `msgstate` to `MSGSTATE_ENCRYPTED`.
  * Initialize the double ratcheting.
  * If there is a recent stored message, encrypt it and send it as a Data Message.


#### Receiving a DRE-Auth message

If the message is version 4 and `ALLOW_V4` is not set, ignore this message.
Otherwise:

If `authstate` is `AUTHSTATE_AWAITING_DRE_AUTH`:

  * Verify that the profile signature is valid.
  * Verify that the profile is not expired.
  * If the auth σ is valid, decrypt the DRE message and verify:
    * that the point Y received in the pre-key message is on curve 448.
    * that the B DH public key is from the correct group.

If everything checks out:

  * Compute the ECDH shared secret `K_ecdh = (G1*y)*x`.
  * Transition `authstate` to `AUTHSTATE_NONE`.
  * Transition `msgstate` to `MSGSTATE_ENCRYPTED`.
  * Initialize the double ratcheting.
  * If there is a recent stored message, encrypt it and send it as a Data Message.

Otherwise, ignore the message. This may cause the sender to be in an invalid
`msgstate` equals `MSGSTATE_ENCRYPTED`, but it can be detected as soon as she
sends the next data message - which won't be possible to be decrypted and will
be replied with an OTR error message.


#### User types a message to be sent

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * If `REQUIRE_ENCRYPTION` is set:
    * Store the plaintext message for possible retransmission, and send a Query Message.
    * TODO: How are going to handle subsequent occurences of this case?
      Should we simply flood the user with Query Messages until the DAKE ends?
  * Otherwise:
    * If `SEND_WHITESPACE_TAG` is set, and you have not received a plaintext message from this correspondent since last entering `MSGSTATE_PLAINTEXT`, attach the whitespace tag to the message. Send the (possibly modified) message as plaintext.

If `msgstate` is `MSGSTATE_ENCRYPTED`:

  * Encrypt the message, and send it as a Data Message.
  * Store the plaintext message for possible retransmission.

If `msgstate` is `MSGSTATE_FINISHED`:

  * Inform the user that the message cannot be sent at this time.
  * Store the plaintext message for possible retransmission.


#### Receiving a Data Message

If `msgstate` is `MSGSTATE_ENCRYPTED`:

Verify the information in the message. If the verification succeeds:

  * Decrypt the message and display the human-readable part (if non-empty) to the user.
  * Rotate root, chain and mix keys as appropiate.
  * If you have not sent a message to this correspondent in some (configurable) time, send a "heartbeat" message.

If the received message contains a TLV type 1, forget all encryption keys for
this correspondent, and transition `msgstate` to `MSGSTATE_FINISHED`.

Otherwise, inform the user that an unreadable encrypted message was received,
and reply with an Error Message.

If `msgstate` is `MSGSTATE_PLAINTEXT` or `MSGSTATE_FINISHED`:

Inform the user that an unreadable encrypted message was received, and reply
with an Error Message.


#### User requests to end an OTR conversation

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * Do nothing.

If `msgstate` is `MSGSTATE_ENCRYPTED`:

  * Send a Data Message containing a TLV type 1.
  * Transition `msgstate` to `MSGSTATE_PLAINTEXT`.

If `msgstate` is `MSGSTATE_FINISHED`:

  * Transition `msgstate` to `MSGSTATE_PLAINTEXT`.


#### Implementation notes (OR Considerations for networks which allow multiple devices)

* When using a transport network that allows multiple devices to be
  simultaneously logged in with the same peer identifier, make sure to identify
  the other participant by its device-specific identifier and not only the
  peer identifier (for example, using XMPP full JID instead of bare JID).
  Doing so allows establishing an OTR channel at the same time with multiple
  devices from the other participant at the cost of how to expose this to
  the message client (for example, XMPP clients can decide to reply only to
  the device you have more recently received a message from).


#### Things to consider

TODO: This whole section is a big TODO.

* How can we address the problem of multiple Query Messages received while the
  DAKE is in progress?

Example: Alice has `REQUIRE_ENCRYPTION`.

```
| Alice                      | Bob                    |
| Types "Hi", Sends Q1       |                        |
|                            | Receives Q1, Sends ψ1a |
| Types "Hey", Sends Q2      |                        |
| Receives ψ1a, Sends ψ2a    |                        |
| Sends ENC(Ka, "Hi")        |                        |
| Sends ENC(Ka, "Hey")       |                        |
|                            | Receives Q2, Sends ψ1b |
| Types "Yes", ENC(Ka, "Yes")|                        |
|                            | Receives ψ2a           |
|                            | Receives ENC(Ka, "Hi") |
|                            | Receives ENC(Ka, "Hey")|
|                            | Sends ENC(Ka, "Hello") |
| Receives ψ1b, Sends ψ2b    |                        |
| Forget Ka??                |                        |
| Receive ENC(Ka, "Hello")   |                        |
| Can't dec if Ka is gone!!  |                        |
| Types "Yo", ENC(Kb, "Yo")  |                        |
|                            | Receives ψ2b           |
|                            | Forget Ka??            |
```

Note this can also happen regardless of `REQUIRE_ENCRYPTION`: Alice only needs
to send a new Query Message after an OTRv4 channel is established.

In the current protocol messages from the previous conversation (which existed
before the new DAKE has finished) may be lost if received after the ψ2b is sent
(or received). This happens because we reset ratched-id to 0 after the DAKE is
complete.

Handling a new DAKE as a new D-H ratchet (and simply incrementing j) should fix
this by applying the same approach as OTRv3: a new DAKE is considered simply as
a new key exchange.

Another suggested alternative is breaking the OTR channel (by reseting the
`msgstate` variable) at the moment you engage in a new DAKE (a new ψ1 is either
sent of received). This can lead to problems of sending messages unencrypted
unless all the participants have the `REQUIRE_ENCRYPTION` policy.


## Socialist Millionaires Protocol (SMP) version 2

The Socialist Millionaires' Protocol allows two parties with secret information
`x` and `y` respectively to check whether `x == y` without revealing any
additional information about the secrets. The protocol used by OTR is based on
the work of Boudot, Schoenmakers and Traore (2001). A full justification for its
use in OTR is made by Alexander and Goldberg, in a paper published in 2007. The
following is a technical account of what is transmitted during the course of the
protocol.

While data messages are being exchanged, either Alice or Bob may run SMP to
detect impersonation or man-in-the-middle attacks.

We reuse the previously defined generator in Cramer-Shoup of DRE:

`G = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)`

### Overview

Assuming that Alice begins the exchange:

**Alice:**

* Picks random values `a2` and `a3`.
* Picks random values `r2` and `r3`.
* Computes `c2 = HashToScalar(1 || G*r2)` and `d2 = r2 - a2 * c2`.
* Computes `c3 = HashToScalar(2 || G*r3)` and `d3 = r3 - a3 * c3`.
* Sends Bob a SMP message 1 with `G2a = G*a2`, `c2`, `d2`, `G3a = G*a3`, `c3` and `d3`.

**Bob:**

* Picks random values `b2` and `b3`.
* Picks random values `r2`, `r3`, `r4`, `r5` and `r6`.
* Computes `G2b = G*b2` and `G3b = G*b3`.
* Computes `c2 = HashToScalar(3 || G*r2)` and `d2 = r2 - b2 * c2`.
* Computes `c3 = HashToScalar(4 || G*r3)` and `d3 = r3 - b3 * c3`.
* Computes `G2 = G2a*b2` and `G3 = G3a*b3`.
* Computes `Pb = G3*r4` and `Qb = G*r4 + G2*y`, where y is the 'actual secret'.
* Comoutes `cP = HashToScalar(5 || G3*r5 || G*r5 + G2*r6)`, `d5 = r5 - r4 * cP` and `d6 = r6 - y * cP`.
* Sends Alice a SMP message 2 with `G2b`, `c2`, `d2`, `G3b`, `c3`, `d3`, `Pb`, `Qb`, `cP`, `d5` and `d6`.

**Alice:**

* Computes `G2 = G2b*a2` and `G3 = G3b*a3`.
* Picks random values `r4`, `r5`, `r6` and `r7`.
* Computes `Pa = G3*r4` and `Qa = G1*r4 + G2*x`, where x is the 'actual secret'.
* Coumputes `cP = HashToScalar(6 || G3*r5 || G*r5 + G2*r6)`, `d5 = r5 - r4 * cP` and `d6 = r6 - x * cP`.
* Computes `Ra = (Qa - Qb)*a3`.
* Computes `cR = HashToScalar(7 || G*r7 || (Qa - Qb)*r7)` and `d7 = r7 - a3 * cR`.
* Sends Bob a SMP message 3 with `Pa`, `Qa`, `cP`, `d5`, `d6`, `Ra`, `cR` and `d7`.

**Bob:**

* Picks a random value `r7`.
* Computes `Rb = (Qa - Qb)*b3`.
* Computes `Rab = Ra*b3`.
* Computes `cR = HashToScalar(8 || G*r7 || (Qa - Qb)*r7)` and `d7 = r7 - b3 * cR`.
* Checks whether `Rab == Pa - Pb`.
* Sends Alice a SMP message 4 with `Rb`, `cR`, `d7`.

**Alice:**

* Computes `Rab = Rb*a3`.
* Checks whether `Rab == Pa - Pb`.

If everything is done correctly, then `Rab` should hold the value of `Pa - Pb`
times `(G2*a3*b3)*(x - y)`, which means that the test at the end of the protocol
will only succeed if `x == y`. Further, since `G2*a3*b3` is a random number not
known to any party, if `x` is not equal to `y`, no other information is
revealed.


### Secret Information

The secret information x and y compared during this protocol contains not only
information entered by the users, but also information unique to the
conversation in which SMP takes place. Specifically, the format is:

```
Version (BYTE)
  The version of SMP used. The version described here is 2.

Initiator fingerprint (32 BYTEs)
  The fingerprint that the party initiating SMP is using in the current conversation.

Responder fingerprint (32 BYTEs)
  The fingerprint that the party that did not initiate SMP is using in the current conversation.

Secure Session ID
  The SSID described above.

User-specified secret (DATA)
  The input string given by the user at runtime.
```

Then the HashToScalar() of the above becomes the actual secret (`x` or `y`) to
be used in SMP. The additional fields insure that not only do both parties know
the same secret input string, but no man-in-the-middle is capable of reading
their communication either.

### SMP Hash function

In the following actions, there are many places where a SHA512 hash of an integer followed by one or two MPIs is taken. The input to this hash function is:

```
Version (BYTE)
  This distinguishes calls to the hash function at different points in the
  protocol, to prevent Alice from replaying Bob's zero knowledge proofs or
  vice versa.

First MPI (MPI)
  The first MPI given as input, serialized in the usual way.

Second MPI (MPI)
  The second MPI given as input, if present, serialized in the usual way. If
  only one MPI is given as input, this field is simply omitted.
```

### SMPv2 messages

SMPv2 messages are sent as TLVs in data messages. For backwards compatibility
with SMP version 1, the TLV type for SMPv2 messages start at 10 (decimal).

#### SMPv2 Abort message

A SMP abort message is a type 10 TLV with no data.

#### SMPv2 message 1

SMP message 1 is sent by Alice to begin a DH exchange to determine two new
generators, `g2` and `g3`. A valid  SMP message 1 is generated as follows:

1. Determine her secret input `x`, which is to be compared to Bob's secret `y`, as specified in the "Secret Information" section.
2. Pick random values `a2` and `a3` (448 bits) in `Z_q`. These will be Alice's exponents for the DH exchange to pick generators.
3. Pick random values `r2` and `r3` (448 bits) in `Z_q`. These will be used to generate zero-knowledge proofs that this message was created according to the protocol.
4. Compute `G2a = G*a2` and `G3a = G*a3`.
5. Generate a zero-knowledge proof that the value a2 is known by setting `c2 = HashToScalar(1 || G*r2)` and `d2 = r2 - a2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value a3 is known by setting `c3 = HashToScalar(2 || G*r3)` and `d3 = r3 - a3 * c3 mod q`.
7. Store the values of `x`, `a2` and `a3` for use later in the protocol.


The SMPv2 message 1 is a TLV type 11 with the following data:

```
question (DATA)
  A user-specified question, which is associated with the user-specified portion of the secret.
  If there is no question input from the user, the length of this is 0 and the
  data is NULL.

G2a (POINT)
  Alice's half of the DH exchange to determine G2.

c2 (MPI), d2 (MPI)
  A zero-knowledge proof that Alice knows the value associated with her transmitted value G2a.

G3a (POINT)
  Alice's half of the DH exchange to determine G3.

c3 (MPI), d3 (MPI)
  A zero-knowledge proof that Alice knows the value associated with her transmitted value G3a.

```

#### SMP message 2

SMP message 2 is sent by Bob to complete the DH exchange to determine the new
generators, g2 and g3. It also begins the construction of the values used in the
final comparison of the protocol. A valid SMP message 2 is generated as follows:

1. Determine Bob's secret input `y`, which is to be compared to Alice's secret `x`.
2. Pick random values `b2` and `b3` (448 bits) in `Z_q`. These will used during the DH exchange to pick generators.
3. Pick random values `r2`, `r3`, `r4`, `r5` and `r6` (448 bits) in `Z_q`. These will be used to add a blinding factor to the final results, and to generate zero-knowledge proofs that this message was created honestly.
4. Compute `G2b = G*b2` and `G3b = G*b3`.
5. Generate a zero-knowledge proof that the value `b2` is known by setting `c2 = HashToScalar(3 || G*r2)` and `d2 = r2 - b2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value `b3` is known by setting `c3 = HashToScalar(4 || G*r3)` and `d3 = r3 - b3 * c3 mod q`.
7. Compute `G2 = G2a*b2` and `G3 = G3a*b3`.
8. Compute `Pb = G3*r4` and `Qb = G*r4 + G2*y`.
9. Generate a zero-knowledge proof that `Pb` and `Qb` were created according to the protocol by setting `cP = HashToScalar(5 || G3*r5 || G*r5 + G2*r6)`, `d5 = r5 - r4 * cP mod q` and `d6 = r6 - y * cP mod q`.
10. Store the values of `G3a`, `G2`, `G3`, `b3`, `Pb` and `Qb` for use later in the protocol.


The SMP message 2 is a TLV type 12 with the following data:

```
G2b (POINT)
  Bob's half of the DH exchange to determine G2.

c2 (MPI), d2 (MPI)
  A zero-knowledge proof that Bob knows the exponent associated with his transmitted value G2b.

G3b (POINT)
  Bob's half of the DH exchange to determine G3.

c3 (MPI), d3 (MPI)
  A zero-knowledge proof that Bob knows the exponent associated with his transmitted value G3b.

Pb (POINT), Qb (POINT)
  These values are used in the final comparison to determine if Alice and Bob share the same secret.

cP (MPI), d5 (MPI), d6 (MPI)
  A zero-knowledge proof that Pb and Qb were created according to the protocol given above.
```


#### SMP message 3

SMP message 3 is Alice's final message in the SMP exchange. It has the last of
the information required by Bob to determine if `x = y`. A valid SMP message 1
is generated as follows:

1. Pick random values `r4`, `r5`, `r6` and `r7` (448 bits) in `Z_q`. These will be used to add a blinding factor to the final results, and to generate zero-knowledge proofs that this message was created honestly.
2. Compute `G2 = G2b*a2` and `G3 = G3b*a3`.
3. Compute `Pa = G3*r4` and `Qa = G*r4 + G2*x`.
4. Generate a zero-knowledge proof that `Pa` and `Qa` were created according to the protocol by setting `cP = HashToScalar(6 || G3*r5 || G*r5 + G2*r6)`, `d5 = r5 - r4 * cP mod q` and `d6 = r6 - x * cP mod q`.
5. Compute `Ra = (Qa - Qb) * a3`.
6. Generate a zero-knowledge proof that `Ra` was created according to the protocol by setting `cR = HashToScalar(7 || G*r7 || (Qa - Qb)*r7)` and `d7 = r7 - a3 * cR mod q`.
7. Store the values of `G3b`, `Pa - Pb`, `Qa - Qb` and `Ra` for use later in the protocol.

The SMP message 3 is a TLV type 13 with the following data:

```
Pa (POINT), Qa (POINT)
  These values are used in the final comparison to determine if Alice and Bob share the same secret.

cP (MPI), d5 (MPI), d6 (MPI)
  A zero-knowledge proof that Pa and Qa were created according to the protocol given above.

Ra (POINT)
  This value is used in the final comparison to determine if Alice and Bob share the same secret.

cR (MPI), d7 (MPI)
  A zero-knowledge proof that Ra was created according to the protocol given above.
```


#### SMP message 4

SMP message 4 is Bob's final message in the SMP exchange. It has the last of the
information required by Alice to determine if `x = y`. A valid SMP message 4 is
generated as follows:

1. Pick a random value `r7` (448 bits) in `Z_q`. This will be used to generate Bob's final zero-knowledge proof that this message was created honestly.
2. Compute `Rb = (Qa - Qb) * b3`.
3. Generate a zero-knowledge proof that `Rb` was created according to the protocol by setting `cR = HashToScalar(8 || G*r7 || (Qa - Qb)*r7)` and `d7 = r7 - b3 * cR mod q`.

The SMP message 4 is a TLV type 14 with the following data:

```
Rb (POINT)
  This value is used in the final comparison to determine if Alice and Bob share the same secret.

cR (MPI), d7 (MPI)
  A zero-knowledge proof that Rb was created according to the protocol given above.
```


### The SMP state machine

Whenever the OTR message state machine has `MSGSTATE_ENCRYPTED` set (see below),
the SMP state machine may progress. If at any point `MSGSTATE_ENCRYPTED` becomes
unset, SMP must abandon its state and return to its initial setup. The SMP state
consists of one main variable, as well as information from the partial
computations at each protocol step.


#### Expected Message

This main state variable for SMP controls what SMP-specific TLVs will be
accepted. This variable has no effect on type 0 or type 1 TLVs, which are always
allowed. smpstate can take one of four values:

```
SMPSTATE_EXPECT1
  This state indicates that only SMP message 1 or SMP message 1Q should be accepted. This is the default state when SMP has not yet begun. This state is also reached whenever an error occurs or SMP is aborted, and the protocol must be restarted from the beginning.

SMPSTATE_EXPECT2
  This state indicates that only SMP message 2 should be accepted.

SMPSTATE_EXPECT3
  This state indicates that only SMP message 3 should be accepted.

SMPSTATE_EXPECT4
  This state indicates that only SMP message 4 should be accepted.
```


#### State Transitions

There are 7 actions that an OTR client must handle to support SMP version 2:

```
User actions:
  User requests to begin SMP
  User requests to abort SMP

Received TLVs:
  SMP Message 1
  SMP Message 2
  SMP Message 3
  SMP Message 4
  SMP Abort Message
```

The following sections outline what is to be done in each case. They all assume
that `MSGSTATE_ENCRYPTED` is set. For simplicity, they also assume that Alice
has begun SMP, and Bob is responding to her.


#### User requests to begin SMP

If smpstate is not set to `SMPSTATE_EXPECT1`:

SMP is already underway. If you wish to restart SMP, send a SMP abort to the
other party and then proceed as if smpstate was `SMPSTATE_EXPECT1`. Otherwise,
you may simply continue the current SMP instance.

If smpstate is set to `SMPSTATE_EXPECT1`:

* Send SMP message 1.
* Set smpstate to `SMPSTATE_EXPECT2`.


#### User requests to abort SMP

In all cases, send a TLV with SMP abort to the correspondent and set smpstate to
`SMPSTATE_EXPECT1`.


#### Receiving a SMP message 1

If smpstate is not `SMPSTATE_EXPECT1`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Alice.

If smpstate is `SMPSTATE_EXPECT1`:

* Verify Alice's zero-knowledge proofs for G2a and G3a:
  1. Check that both `G2a` and `G3a` are points in the curve.
  2. Check that `c2 = HashToScalar(1 || G*d2 + G2a*c2)`.
  3. Check that `c3 = HashToScalar(2 || G*d3 + G3a*c3)`.
* Create a SMP message 2 and send it to Alice.
* Set smpstate to `SMPSTATE_EXPECT3`.


#### Receiving a SMP message 2

If smpstate is not `SMPSTATE_EXPECT2`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT2`:

* Verify Bob's zero-knowledge proofs for `G2b`, `G3b`, `Pb` and `Qb`:
    1. Check that `G2b`, `G3b`, `Pb` and `Qb` are points in the curve.
    2. Check that `c2 = HashToScalar(3 || G*d2 + G2b*c2)`.
    3. Check that `c3 = HashToScalar(4 || G*d3 + G3b*c3)`.
    4. Check that `cP = HashToScalar(5 || G3*d5 + Pb*cP || G*d5 + G2*d6 + Qb*cP)`.
* Create a type SMP message 3 and send it to Bob.
* Set smpstate to `SMPSTATE_EXPECT4`.


#### Receiving a SMP message 3

If smpstate is not `SMPSTATE_EXPECT3`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT3`:

* Verify Alice's zero-knowledge proofs for `Pa`, `Qa` and `Ra`:
  1. Check that `Pa`, `Qa` and `Ra` are points in the curve.
  2. Check that `cP = HashToScalar(6 || G3*d5 + Pa*cP || G*d5 + G2*d6 + Qa*cP)`.
  3. Check that `cR = HashToScalar(7 || G*d7 + G3a*cR || (Qa - Qb)*d7 + Ra*cR)`.
* Create a SMP message 4 and send it to Alice.
* Check whether the protocol was successful:
  1. Compute `Rab = Ra*b3`.
  2. Determine if `x = y` by checking the equivalent condition that `Pa - Pb = Rab`.
* Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from Alice.


#### Receiving a SMP message 4

If smpstate is not `SMPSTATE_EXPECT4`:
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is SMPSTATE_EXPECT4:

* Verify Bob's zero-knowledge proof for R_b:
   1. Check that `R_b` is `>= 2` and `<= modulus-2`.
   2. Check that `cR = SHA3-512(8, g1*D7 g3_b*cR, (Q_a / Q_b)*D7 + R_b*cR)`.

* Check whether the protocol was successful:
    1. `Compute R_a_b = R_b*a3`.
    2. Determine if `x = y` by checking the equivalent condition that `(P_a / P_b) = R_a_b`.

Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from Bob.


## Appendices

### ROM DRE

The DRE scheme consists of three functions:

`PK, SK = DRGen()`, a key generation function.
`γ = DREnc(PK1, PK2, m)`, an encryption function.
`m = DRDec(PK1, PK2, SKi, γ)`, a decryption function.

#### Domain parameters

The Cramer-Shoup scheme uses a group (G, q, G1, G2). This is a group with the
same q as Curve 448. The generators G1 and G2 are:

G1 = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)

G2 = (117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495, 19)

#### Dual Receiver Key Generation: DRGen()

1. Pick random values `x1, x2, y1, y2, z` in Z_q (56 bytes each).
2. Compute group elements
  - `C = G1*x1 + G2*x2`
  - `D = G1*y1 + G2*y2`
  - `H = G1*z`.
3. The public key is `PK = {C, D, H}` and the secret key is `SK = {x1, x2, y1, y2, z}`.

#### Dual Receiver Encryption: DREnc(PK1, PK2, m)

Let `{C1, D1, H1} = PK1` and `{C2, D2, H2} = PK2`

1. Pick random values `k1, k2, r` in Z_q and compute `K = G1*r`.
2. For i ∈ {1, 2}:
  1. Compute
    - `U1i = G1*ki`
    - `U2i = G2*ki`
    - `Ei = (Hi*ki) + K`
  2. Compute `αi = HashToScalar(U1i || U2i || Ei)`.
  3. Compute `Vi = Ci*ki + Di*(ki * αi)`
3. Compute `K_enc = SHA3-512(K)`. K is compressed from 446 bits to 256 bits because XSalsa20 has a maximum key size of 256.
4. Pick a random 24 bytes `nonce` and compute `φ = XSalsa20-Poly1305_K_enc(m, nonce)`
5. Generate a NIZKPK:
  1. for i ∈ {1, 2}:
    1. Pick random value `ti` in Z_q.
    2. Compute
      - `T1i = G1*ti`
      - `T2i = G2*ti`
      - `T3i = (Ci + Di*αi)*ti`
  2. Compute `T4 = H1*t1 - H2*t2`.
  3. Compute
    - `gV = G1 || G2 || q`
    - `pV = C1 || D1 || H1 || C2 || D2 || H2`
    - `eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2`
    - `zV = T11 || T21 || T31 || T12 || T22 || T32 || T4`
    - `l = HashToScalar(gV || pV || eV || zV)`
  4. Generate for i ∈ {1,2}:
    1. Compute `ni = ti - l * ki (mod q)`.
6. Send `γ = (U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, φ)`.

#### Dual Receiver Decryption: DRDec(PK1, PK2, SKi, γ):

Let `{C1, D1, H1} = PK1`, `{C2, D2, H2} = PK2` and `{x1i, x2i, y1i, y2i, zi} = SKi`.
SKi is the secret key of the person decrypting the message.

1. Parse `γ` to retrieve components
  `(U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, φ) = γ`.
2. Verify NIZKPK:
  1. for j ∈ {1, 2} compute:
    1. `αj = HashToScalar(U1j || U2j || Ej)`
    2. `T1j = G1*nj + U1j*l`
    3. `T2j = G2*nj + U2j*l`
    4. `T3j = (Cj + Dj*αj)*nj + Vj*l`
  2. Compute `T4 = H1*n1 - H2*n2 + (E1-E2)*l`
  3. Compute
    - `gV = G1 || G2 || q`
    - `pV = C1 || D1 || H1 || C2 || D2 || H2`
    - `eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2`
    - `zV = T11 || T21 || T31 || T12 || T22 || T32 || T4`
    - `l' = HashToScalar(gV || pV || eV || zV)`
  4. Verify `l' ≟ l`.
  5. Compute
    - `T1 = U1i*x1i`
    - `T2 = U2i*x2i`
    - `T3 = U1i*y1i`
    - `T4 = U2i*y2i`
  6. Verify `T1 + T2 + (T3 + T4)*αi ≟ Vi`.
3. Recover secret key `K_enc = SHA3-512(Ei - U1i*zi)`. K is compressed from 446 bits to 256 bits because XSalsa20 has a maximum key size of 256.
4. Decrypt `m = XSalsa20-Poly1305_K_enc(φ, nonce)`.

### ROM Authentication

The Authentication scheme consists of two functions:

`σ = Auth(A_2, a_2, {A_1, A_3}, m)`, an authentication function.
`Verif({A_1, A_2, A_3}, σ, m)`, a verification function.

#### Domain parameters

We reuse the previously defined generator in Cramer-Shoup of DRE:

G = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160).

#### Authentication: Auth(A2, a2, {A1, A3}, m):

A2 is the public value associated with a2, that is, `A2 = G*a2`.
m is the message to authenticate.

1. Pick random values `t1, c2, c3, r2, r3` in Z_q.
2. Compute `T1 = G*t1`.
3. Compute `T2 = G*r2 + A2*c2`.
4. Compute `T3 = G*r3 + A3*c3`.
5. Compute `c = HashToScalar(G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Compute `c1 = c - c2 - c3 (mod q)`.
7. Compute `r1 = t1 - c1 * a2 (mod q)`.
8. Send `σ = (c1, r1, c2, r2, c3, r3)`.

#### Verification: Verif({A1, A2, A3}, σ, m)

1. Parse σ to retrive components `(c1, r1, c2, r2, c3, r3)`.
2. Compute `T1 = G*r1 + A1*c1`
3. Compute `T2 = G*r2 + A2*c2`
4. Compute `T3 = G*r3 + A3*c3`
5. Compute `c = HashToScalar(G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Check if `c ≟ c1 + c2 + c3 (mod q)`.

### HashToScalar(d)

d is an array of bytes.

1. Compute `h = SHA3-512(d)` as an unsigned value, big-endian.
2. Return `h (mod q)`

<!--- References -->

[1]: https://www.ietf.org/rfc/rfc3526.txt2 "M. Kojo: More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)"
[2]: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf "N. Unger, I. Goldberg: Improved Techniques for Implementing Strongly Deniable Authenticated Key Exchanges"
[3]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html "Off-the-Record Messaging Protocol version 3"
[4]: https://mikehamburg.com/papers/goldilocks/goldilocks.pdf "M. Hamburg: Ed448-Goldilocks, a new elliptic curve"
[5]: http://www.ietf.org/rfc/rfc7748.txt "A. Langley, M. Hamburg, and S. Turner: Elliptic Curves for Security.” Internet Engineering Task Force; RFC 7748 (Informational); IETF, Jan-2016"
[6]: https://whispersystems.org/docs/specifications/doubleratchet "Trevor Perrin (editor), Moxie Marlinspike: The Double Ratchet Algorithm"
