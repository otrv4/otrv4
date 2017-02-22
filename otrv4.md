# OTR version 4

OTRv4 is a new version of OTR that provides a deniable authenticated key
exchange and better forward secrecy through the use of double ratcheting. OTR
works on top of an existing messaging protocol, like XMPP.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)
2. [High Level Overview](#high-level-overview)
3. [Assumptions](#assumptions)
4. [Security Properties](#security-properties)
5. [Notation and parameters](#notation-and-parameters)
6. [Data Types](#data-types)
7. [Conversation Initialization](#conversation-initialization)
  1. [Requesting conversation with older OTR versions](#requesting-conversation-with-older-otr-versions)
  2. [User Profile](#user-profile)
    1. [Creating a User Profile](#creating-a-user-profile)
    2. [Establishing Versions](#establishing-versions)
    3. [Version Priority](#version-priority)
    4. [Renewing a Profile](#renewing-a-profile)
    5. [Creating a User Profile Signature](#creating-a-user-profile-signature)
    6. [Verify a User Profile Signature](#verify-a-user-profile-signature)
    7. [User Profile Signature](#user-profile-signature)
    8. [User Profile Data Type](#user-profile-data-type)
  3. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
    1. [DAKE Overview](#dake-overview)
    2. [Identity message](#identity-message)
    3. [DRE-Auth message](#dre-auth-message)
8. [Data exchange](#data-exchange)
  1. [Data Message](#data-message)
  2. [Revealing MAC Keys](#revealing-mac-keys)
  3. [Fragmentation](#fragmentation)
9. [The protocol state machine](#the-protocol-state-machine)
  1. [Protocol States](#protocol-states)
  2. [Protocol Events](#protocol-events)
  3. [User requests to start an OTR conversation](#user-requests-to-start-an-otr-conversation)
    1. [Query Messages](#query-messages)
    2. [Whitespace Tags](#whitespace-tags)
  4. [Receiving plaintext without the whitespace tag](#receiving-plaintext-without-the-whitespace-tag)
  5. [Receiving plaintext with the whitespace tag](#receiving-plaintext-without-the-whitespace-tag)
  6. [Receiving a Query Message](#receiving-a-query-message)
  7. [Receiving OTRv3 Specific Messages](#receiving-otrv3-specific-messages)
  8. [Receiving an Identity Message](#receiving-an-identity-message)
  9. [Sending a DRE-Auth Message](#sending-a-dre-auth-message)
  10. [Receiving a DRE-Auth Message](#receiving-a-dre-auth-message)
  11. [Sending an encrypted data message](#sending-an-encrypted-data-message)
  12. [Receiving an encrypted data message](#receiving-an-encrypted-data-message)
  13. [Receiving an error message](#receiving-an-error-message)
  14. [User requests to end an OTR conversation](#user-requests-to-end-an-otr-conversation)
  15. [Receiving a TLV type 1 (Disconnect) Message](#receiving-a-tlv-type-1-disconnect-message)
10. [Socialist Millionaires' Protocol (SMP)](#socialist-millionaires-protocol-smp)
11. [Implementation Notes](#implementation-notes)
12. [Forging Transcripts](#forging-transcripts)

[Appendices](#appendices)

  1. [ROM DRE](#rom-dre)
  2. [ROM Authentication](#rom-authentication)
  3. [HashToScalar](#hashToScalar)
  4. [Modify an encrypted data message](#modify-an-encrypted-data-message)

## Main Changes over Version 3

- Security level raised to 224 bits and based on elliptic curve cryptography
  (ECC).
- Additional protection against transcript decryption in the case of ECC
  compromise.
- The cryptographic primitives and protocols have been updated:
  - Deniable authenticated key exchange using Spawn [\[1\]](#references).
  - Key management using the Double Ratchet Algorithm [\[2\]](#references).
  - Upgraded SHA-1 and SHA-2 to SHA-3.
  - Switched from AES to XSalsa20.
- Explicit instructions for producing forged transcripts using the same
  functions used to conduct honest conversations.

## High Level Overview

```
Alice                                            Bob
--------------------------------------------------------------------------------
Requests OTR conversation           ------------->
Establishes Conversation with DAKE  <------------>  Establishes Conversation with DAKE
Exchanges Data Messages             <------------>  Exchanges Data Messages
```

An OTRv4 conversation can begin after one participant requests a conversation.
This includes an advertisement of which versions they support. If the other
participant supports one of these versions, a deniable, authenticated key exchange
(DAKE) is used to establish a secure channel. Encrypted messages are then
exchanged in this secure channel with forward secrecy.

## Assumptions

Both participants are online at the start of a conversation.

Messages in a conversation can be exchanged over an insecure channel, where an
attacker can eavesdrop or interfere with the encrypted messages.

The network model provides in-order delivery of messages, but some messages
may not be delivered.

OTRv4 does not protect against an active attacker performing Denial of Service
attacks to reduce availability.

## Security Properties

OTRv4 does not take advantage of quantum resistant algorithms for several
reasons. It aims to be easy to implement in today's environments within a
year. Current quantum resistant algorithms and their respective
implementations are not ready enough to fit in that time frame. As a result,
the protections mentioned in the following paragraphs only apply to non-quantum
adversaries. The only exception is the usage of a "mix key" to provide
some post-conversation transcript protection against potential weaknesses with
elliptic curves and the early arrival of quantum computers.

In the DAKE, although access to one of the participant's private keys is
required for authentication, both participants can deny having used their private,
long term keys in this process. An external cryptographic expert will be able to
prove that one person between the two used their long term private key for the
authentication, but they will not be able to identify whose key was used.

Once an OTRv4 channel has been created with the DAKE, all data messages
transmitted through this channel are confidential and their integrity to the
participants is protected. In addition, the MAC keys used to validate
each message are revealed. This allows for forgeability of the data messages
and consequent deniability of their contents.

If key material for a particular data message is compromised, previous messages
are protected. Future messages are protected by the Diffie-Hellman and Elliptic
Curve Diffie-Hellman ratchets.

## Notation and parameters

This section contains information needed to understand the parameters,
variables and arithmetic used in the specification.

### Notation

Scalars and secret keys are in lower case, such as `x` or `y`. Points and
public keys are in upper case, such as `P` or `Q`.

Addition and subtraction of elliptic curve points `A` and `B` are `A + B` and
`A - B`. Addition of a point to another point generates a third point. Scalar
multiplication of an elliptic curve point `B` with a scalar `a` yields a
new point: `C = B * a`.

The concatenation of byte sequences `I` and `J` is `I || J`. In this case, `I`
and `J` represent a fixed-length byte sequence encoding the respective values.
See section [Data Types](#data-types) for encoding and decoding details.

### Elliptic Curve Parameters

OTRv4 uses the Ed448-Goldilocks [\[3\]](#references) elliptic curve [\[4\]](#references), which defines the
following parameters:

```
Equation
	x^2 + y^2 = 1 - 39081 * x^2 * y^2

Coordinates:
	Extended Homogenous

Base point (G1)
  (x=11781216126343694673728248434331006466518053535701637341687908214793
     9404277809514858788439644911793978499419995990477371552926308078495,
   y=19)

  (x=0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147
     eaaf3932d94c63d96c170033f4ba0c7f0de840aed939f,
   y=0x13)

Cofactor (c)
  1 (this cofactor value is due to the use of Decaf [\[6\]](#references))

Identity point (I)
  (x=0,
   y=1)

Field prime (p)
  2^448 - 2^224 - 1

Order of base point (q) [prime; q < p; q * G1 = I]
  2^446 - 13818066809895115352007386748515426880336692474882178609894547503885

Number of bytes in p (|p|)
  56 bytes

Number of bytes in q (|q|)
  55 bytes

Non-square element in Z_p (d)
  -39081
```

A scalar modulo `q` is a "field element", and should be encoded and decoded
using the rules for multi-precision integers (MPIs). MPIs are defined on [Data Types](#data-types) section.

### 3072-bit Diffie-Hellman Parameters

For the Diffie-Hellman group computations, the group is the one defined in RFC
3526 [\[5\]](#references) with a 3072-bit modulus (hex, big-endian):

```
Prime (dh_p):
  2^3072 - 2^3008 - 1 + 2^64 * (integer_part_of(2^2942 * π) + 1690314)

Hexadecimal value of dh_p:
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

Generator (g3)
  2

Cofactor (dh_c)
  2

Order of dh_p (dh_q; prime; dh_q = (dh_p - 1) / 2):
  2^3071 - 2^3007 - 1 + 2^63 * (integer_part_of(2^2942 * π) + 1690314)

```

Note that this means that whenever you see an operation on a field element
from the above group, the operation should be done modulo the above prime.

## Data Types

OTRv4 uses many of the data types specified in OTRv3:

```
Bytes (BYTE):
  1 byte unsigned value
Shorts (SHORT):
  2 byte unsigned value, big-endian
Ints (INT):
  4 byte unsigned value, big-endian
Multi-precision integers (MPI):
  4 byte unsigned len, big-endian
  len byte unsigned value, big-endian
  (MPIs must use the minimum-length encoding; i.e. no leading 0x00 bytes.
   This is important when calculating public key fingerprints.)
Opaque variable-length data (DATA):
  4 byte unsigned len, big-endian
  len byte data
```

OTRv4 also uses the following data types:

```
Nonce (NONCE):
  24 bytes data

Message Authentication Code (MAC):
  64 bytes MAC data

ED448 point (POINT):
  56 bytes data

User Profile (USER-PROF):
  Detailed in "User Profile Data Type" section
```

In order to serialize and deserialize the point, use Encode and Decode as
defined on Appendix A.1 (Encoding) and A.2 (Decoding) in Mike Hamburg's Decaf
paper [\[6\]](#references). These functions work as follows:


#### Encode

Using the Jacobi quartic, a point `P` can by encoded by the s-coordinate of the
coset representative `(s, t)`, where `s` is non-negative and finite, and `t /s`
is non-negative or infinite.

It is wished to compute `s` as
`(1 ± sqrt(1 - (a * x)^2)) / a * x` and `t / s` = `∓ 2 * sqrt(1 - (a * x) ^ 2) / x * y`.

1. From the curve equation, is known that:
`(1 - ax^2) * (1 - y^2) = 1 + (a * x)^2 * y^2 - (y^2 + (a * x)^2) = (a - d) * x^2 * y^2`,
so that `sqrt(1 - (a * x^2)) / x * y = ± sqrt((a - d) / (1 - y^2))`.
Note that in extended homogenous coordinates:
`1/x^2 = (a - (d * y)^2) / 1 - y^2) = ((a * Z)^2 - (d * Y)^2) / (Z^2 - Y^2)`,
so that `1/x = ((a * Z * X) - (d * Y * T))/ (Z^2 - Y^2)`
2. Compute `r = 1/ sqrt((a - d) * (Z + Y) * (Z - Y))`
3. Compute `u = (a - d) * r`
4. Compute `r = -r` if `-2 * u * Z` is negative
5. Compute `s = | u * (r * ((a * Z * X) - (d * Y * T)) + Y) / a|`

#### Decode

Given s, compute:
`(x, y) = (2 * s / (1 + (a * s)^2),
(1 - (a * s)^ 2 / sqrt(a^2 * s^4 + (2 * a - 4 * d) * s^2 + 1))`

1. Compute `X = 2 * s`
2. Compute `Z = 1 + a * s^2`
3. Compute `u = Z^2 - (4 * d) * s^2`
4. Compute `v` equals
   1. `1 / sqrt(u * s^2)` if `u * s^2` is square and non-zero
	2. `0` if `u * s^2 = 0`
	3. reject if `u * s^2` is not square
5. Compute `v` = `-v` if `u * v` is negative
6. Compute `w = v * s * (2 - Z)`
7. Compute `w = w + 1` if `s = 0`
8. Compute `Y = w * Z`
9. Compute `T = w * X`
10. Compute `P = (X : Y : Z : T)`

### DRE messages and Auth

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
    Where (U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2) =
    DREnc(pubA, pubB, k)
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
    Where (c1, r1, c2, r2, c3, r3) = Auth(A_2, a_2, {A_1, A_2, A_3}, m)
```

### Public keys and fingerprints

OTRv4 introduces a new type of public key:

```
OTR public authentication Cramer-Shoup key (CRAMER-SHOUP-PUBKEY):

  Pubkey type (SHORT)
    Cramer-Shoup public keys have type 0x0010

    C (POINT)
    D (POINT)
    H (POINT)
      (C, D, H) are the Cramer-Shoup public key parameters
```

OTRv4 public keys have fingerprints, which are hex strings that serve as
identifiers for the public key. The fingerprint is calculated by taking the
SHA3-512 hash of the byte-level representation of the public key.

### TLV Types

OTRv4 supports the same TLV record types from OTRv3.

### OTR Error Messages

Any message containing the string "?OTR Error:" is an OTR Error Message. The
following part of the message should contain human-readable details of the
error. The message may also include a specific code at the beginning e.g. "?OTR
Error: ERROR_N:". This code is used to identify which error is being
received for optional internationalization of the message.

Error Code List:

```
ERROR_1:
  Message cannot be decrypted
```

## Key management

In the DAKE, OTRv4 makes use of long-term Cramer-Shoup keys, ephemeral Elliptic
Curve Diffie-Hellman (ECDH) keys, and ephemeral Diffie-Hellman (DH) keys.

For exchanging data messages, OTRv4 makes use of both the DH ratchet (with ECDH)
and the symmetric-key ratchet from the Double Ratchet algorithm [\[2\]](#references). A
cryptographic ratchet is a one-way mechanism for deriving new cryptographic keys
from previous keys. New keys cannot be used to calculate the old keys.

OTRv4 adds new 3072-bit (384-byte) DH keys, called the mix key pair, to the
Double Ratchet algorithm. These keys are used to protect transcripts of data
messages in a case where ECC is broken. During the DAKE, both parties agree upon
the first set of DH keys. Then, during every third DH ratchet in the Double
Ratchet, a new key is agreed upon. Between each DH mix key ratchet, both sides
will conduct a symmetric mix key ratchet.

The following variables keep state as the ratchet moves forward:

```
State variables:
  i: the current ratchet id.
  j: the current sending message id
  k: the current receiving message id.

Key variables:
  'root[i]': the Root key for the ratchet i.
  'chain_s[i][j]': the sending chain key for the message j in the ratchet i.
  'chain_r[i][k]': the receiving chain key for the message k in the ratchet i.
  'our_ecdh': our current ECDH ephemeral key pair.
  'their_ecdh': their ECDH ephemeral public key.
  'our_dh': our DH ephemeral key pair.
  'their_dh': their DH ephemeral public key.
  'mix_key': the SHA3-256 of the DH shared secret previously computed.
  'mac_keys_to_reveal': the mac keys to be revealed in next data message sent.
```

The previously mentioned state variables are incremented and the key variable values
are replaced by these events:

* When you start a new [DAKE](#dake-overview) by sending or receiving an [Identity message](#identity-message).
* Upon completing the DAKE by sending or receiving a [DRE-Auth Message](#dre-auth-message).
* [When you send and receive a Data Message](#data-exchange)
* [When you receive a TLV type 1 (Disconnect)](#receiving-a-tlv-type-1-disconnect-message)

### Generating ECDH and DH keys

```
generateECDH()
  pick a random value r from Z_q
  return our_ecdh.public = G1 * r, our_ecdh.secret = r

generateDH()
  pick a random value r (80 bytes)
  return our_dh.public = g3 ^ r, our_dh.secret = r
```

### Shared secrets

```
k_dh:
  The serialized 3072-bit DH shared secret computed from a DH exchange.
  This is serialized as a big-endian unsigned integer.

mix_key:
  A SHA3-256 hash of the shared DH key SHA3-256(k_dh).

K_ecdh:
  The serialized ECDH shared secret computed from an ECDH exchange.
  This is serialized as a POINT.

K:
  The mixed shared secret is the final shared secret derived from both the
  DH and ECDH shared secrets.
```

### Deciding between chain keys

Once the DAKE completes, Alice and Bob derive two chain keys from the mixed
shared secret. Both sides will compare their public keys to choose which chain
key will be used for encrypting and decrypting data messages:

- Alice (and, similarly, Bob) determines if she is the "low" end or the "high"
  end of this ratchet. If Alice's ephemeral ECDH public key is numerically
  greater than Bob's public key, then she is the "high" end. Otherwise, she is
  the "low" end.

- Alice selects the chain keys for sending and receiving:
  - If she is the "high" end, use `Ca` as the sending chain key (`chain_s`)
  and `Cb` as the receiving chain key (`chain_r`).
  - If she is the "low" end, use `Cb` as the sending chain key (`chain_s`)
  and Ca as the receiving chain key (`chain_r`).

```
decide_between_chain_keys(Ca, Cb):
  if compare(our_ecdh.public, their_ecdh) > 0
    return Ca, Cb
  else
    return Cb, Ca
```

### Deriving Double Ratchet keys

```
derive_ratchet_keys(K):
  R = SHA3-512(0x01 || K)
  Ca = SHA3-512(0x02 || K)
  Cb = SHA3-512(0x03 || K)
  return R, decide_between_chain_keys(Ca, Cb)
```

### Rotating ECDH keys and mix key

Before sending the first reply (i.e. a new message considering a previous
message has been received) the sender will rotate their ECDH keys and mix key.
This is for the computation of K (see "Deriving Double Ratchet Keys"). The
following data messages will advertise a new ratchet id as `i + 1`.

Before rotating the keys:

  * Increment the current ratchet id (`i`) by 1.
  * Reset the next sent message id (`j`) to 0.

To rotate the ECDH keys:

  * Generate a new ECDH key pair and assign it to `our_ecdh = generateECDH()`.
  * Calculate `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.
  * Securely delete `our_ecdh.secret`.

To rotate the mix key:

  * If `i % 3 == 0`:

    * Generate the new DH key pair `our_dh = generateDH()`.
    * Calculate `k_dh = DH(our_dh.secret, their_dh.public)`.
    * Calculate a `mix_key = SHA3-256(k_dh)`.
    * Securely delete `our_dh.secret`.

  Otherwise:

   * Derive and securely overwrite `mix_key = SHA3-256(mix_key)`.

### Deriving new chain keys

When sending data messages, you must derive the chain key:

```
derive_chain_key(C, i, j):
  C[i][j] = SHA3-512(C[i][j-1])
  return C[i][j]
```

### Computing chain keys

When receiving data messages, you must compute the chain key:

```
compute_chain_key(C, i, k):
  if C[i][k] does not exist:
    C[i][k] = SHA3-512(compute_chain_key(C, i, k-1))
  return C[i][k]
```

### Calculating encryption and MAC keys

When sending or receiving data messages, you must calculate the message keys:

```
derive_enc_mac_keys(chain_key):
  MKenc = SHA3-256(0x01 || chain_key)
  MKmac = SHA3-512(0x02 || chain_key)
  return MKenc, MKmac
```

### Resetting state variables and key variables

The state variables are set to 0 and the key variables are set to NIL for
this channel.

## Conversation Initialization

OTRv4 will initialize through a [Query Message or a Whitespace
Tag](#user-requests-to-start-an-otr-conversation). After this, the conversation is
authenticated using DAKE.

### Requesting conversation with older OTR versions

Bob might respond to Alice's request or notification of willingness to start a
conversation using OTRv3. If this is the case and Alice supports version 3,
the protocol falls back to OTRv3 [\[7\]](#references). If Alice does not support version 3,
then this message is ignored.

### User Profile

OTRv4 introduces a user profile. The user profile contains the Cramer-Shoup
long term public key, signed information about supported versions, a signed
profile expiration date, and an optional transition signature.

Each participant maintains a user profile for authentication in the DAKE and for
publication. Publishing the user profile allows users to repudiate their
participation in OTRv4 conversations. When a user profile is published, it is
available from a public location, such as a server. Each implementation may
decide how to publish the profile. For example, one client may publish profiles
to a server pool (similar to a keyserver pool, where PGP public keys can be
published). Another client may use XMPP's publish-subscribe extension (XEP-0060 [\[8\]](#references))
for publishing profiles.

When the user profile expires, it should be updated. Client implementation
should determine the frequency of user's profile expiration and renewal. The
recommended expiration time is two weeks.

Both parties include the user profile in the DAKE. Participants in the DAKE do
not request the profile from the site of publication. Both the published profile
and the profile used in the DAKE should match each other.

#### Creating a User Profile

To create a user profile, assemble:

1. User's Cramer-Shoup long term public key.
2. Versions: a string corresponding to the user's supported OTR versions.
   A user profile can advertise multiple OTR versions. The format is
   described under the section ["Establishing Versions"](#establishing-versions)
   below.
3. Profile Expiration: Expiration date in standard Unix 64-bit format
   (seconds since the midnight starting Jan 1, 1970, UTC, ignoring leap seconds)
4. Profile Signature: One of the Cramer-Shoup secret key values (`z`) and its
   generator (`G1`) is used to create signatures of the entire profile
   excluding the signature itself. The size of the signature is 112 bytes.
   It is created using the [Ed448 signature algorithm](#user-profile-signature).
5. Transition Signature (optional): A signature of the profile excluding
   Profile Signatures and itself signed by the user's OTRv3 DSA key. The
   transitional signature that enables contacts that trust user's version 3
   DSA key to trust the user's profile in version 4. This is only used if the
   user supports versions 3 and 4.

After the profile is created, it must be published in a public place, like an
untrusted server.

#### Establishing Versions

A valid versions string can be created by concatenating supported version numbers
together in any order. For example, a user who supports versions 3 and 4
will have the version string "43" or "34" in their profile (2 bytes). A user who only
supports version 4 will have "4" (1 byte). Thus, a version string has varying size,
and it is represented as a DATA type with its length specified.

Invalid version strings contain "2" or "1". The OTRv4 specification supports up
to OTR version 3, and thus do not support versions 2 and 1, i.e. version strings of
"32" or "31".

#### Version Priority

OTRv4 addresses version rollback attacks by prioritizing later versions over older
versions. For example, in the case where both participants support versions 3 and 4,
both will default to using 4. In another case where one participant only supports
version 3 and the other supports version 3 and 4, version 3 will be used. Each
client should keep track of which versions are more recent and thus prioritize
them while processing versions in the DAKE.

#### Renewing a Profile

If a renewed profile is not published in a public place, the user's
participation deniability is at risk. Participation deniability is also at risk
if the only publicly available profile is expired. In addition, an expired
profile received in the DAKE is considered invalid.

Before the profile expires, the user must publish an updated profile with a
new expiration date. The client establishes the frequency of expiration - this
can be configurable. A recommended value is two weeks.

#### Creating a User Profile Signature

The user profile signature is based on the Ed448 Schnorr's signature algorithm described
by Mike Hamburg. Hamburg gives an overview of how the signature is created in his paper [_Ed448-Goldilocks,
a new elliptic curve_](#references), and his [implementation function decaf\_448\_sign\_shake](https://sourceforge.net/p/ed448goldilocks/code/ci/decaf/tree/src/decaf_crypto.c#l117)
provides more detail.

OTRv4 uses the following steps to create a signature:

1. Derive an intermediary nonce by first using SHA3 SHAKE256 to hash the message,
   a random value `random_v`, and the specific string "decaf\_448\_sign\_shake". Decode and
   reduce this output into a scalar within the order of the base point
   [q](#elliptic-curve-parameters).
   ```
   random_v = new_random_value()
   output = SHAKE256(message || random_v || "decaf\_448\_sign\_shake")
   intermediary_nonce = decode(output) % q
   ```

2. Use this intermediary nonce to create the temporary signature bytes by computing nonce * G1 and
   encoding the output.
   ```
   temporary_signature_bytes = encode(G1 * intermediary_nonce)
   ```

3. Use SHAKE256 again to hash the message, public key, and the temporary signature bytes.
   The `public_key` is the [`h` value](#dual-receiver-key-generation-drgen) of the Cramer-Shoup
   public key. Decode and reduce this output into a scalar by the order of the base point
   [q](#elliptic-curve-parameters).
   ```
   output = SHAKE256(message || public_key || temporary_signature_bytes)
   challenge = decode(output) % q
   ```

4. Scalar multiply the challenge with the secret key. The `secret_key` is the [`z`
   value](#dual-receiver-key-generation-drgen) of the Cramer-Shoup private key.
   Derive the final nonce by scalar subtracting the product of the multiplication
   from the intermediary nonce.
   ```
   nonce = intermediary_nonce - challenge * secret_key
   ```

5. Concatenate the final nonce and the temporary signature bytes into the full signature, with the nonce first.
   The nonce and the temporary signature are each 56 bytes each, so the final result is 112 bytes, or
   896 bits.

#### Verify a User Profile Signature

Hamburg also gives an overview of how to verify the signature in the [implementation function
decaf\_448\_verify\_shake](https://sourceforge.net/p/ed448goldilocks/code/ci/decaf/tree/src/decaf_crypto.c#l163).

He uses the following steps to verify the signature:

1. Divide the full signature into the nonce bytes and the temporary signature bytes. The nonce is the first
   56 bytes and the temporary signature bytes are the second 56 bytes.

2. Derive the challenge by using SHAKE256 to hash the message, public key, and the temporary signature bytes.
   The public key is retrieved from [`h` value](#dual-receiver-key-generation-drgen) of the Cramer-Shoup long term public key in the profile.
   Decode and reduce this output into a scalar by the order of the base point [q](#elliptic-curve-parameters).
   ```
   output = SHAKE256(message || public_key || temporary_signature_bytes)
   challenge = decode(output) % q
   ```

3. Decode the temporary signature and the public key into points. This includes verifying that the temporary
   signature and the public key are points on the curve 448.
   ```
   temporary_signature_point = decode_point_from(temporary_signature_bytes)
   public_key_point = decode_point_from(public_key)
   ```

4. Decode the nonce into a scalar. This includes verifying that the nonce is a scalar within order of the
   base point.
   ```
   nonce = decode_into_scalar(nonce_bytes)
   ```

5. Compute the double scalar multiplication of the Ed448 base point, the `public_key`, the `nonce`, and the `challenge`.
   ```
   result_point  = G1 * nonce + public_key_point * challenge
   ```

6. Check that the `result_point` and the `temporary_signature_point` are equal. If they are equal, the signature is valid.

#### User Profile Data Type

SIG below refers to the OTR version 3 DSA Signature with the structure:

DSA signature (SIG):
  (len is the length of the DSA public parameter q, which in current implementations must be 20 bytes, or 160 bits)
  len byte unsigned r, big-endian
  len byte unsigned s, big-endian

SCHNORR-SIG refers to the OTR version 4 signature:

Schnorr signature (SCHNORR-SIG):
  (len is the expected length of the signature, which is 112 bytes, or 896 bits)
  len byte unsigned value, big-endian

```
User Profile (USER-PROF):
  Cramer-Shoup public key (CRAMER-SHOUP-PUBKEY)
  Versions (DATA)
  Profile Expiration (PROF-EXP)
  Profile Signature (SCHNORR-SIG)
  (optional) Transitional Signature (SIG)

Profile Expiration (PROF-EXP):
  8 bytes signed value, big-endian
```

### Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the DAKE. This is a way to mutually agree upon
shared keys for the two parties and authenticate one another while providing
participation deniability.

This protocol is derived from the Spawn protocol [\[1\]](#references), which uses dual-receiver
encryption (DRE) and a non-interactive zero-knowledge proof of knowledge
(NIZKPK) for authentication (Auth).

Alice's long-term Cramer-Shoup key-pair is `ska = (x1a, x2a, y1a, y2a, za)` and
`PKa = (Ca, Da, Ha)`. Bob's long-term Cramer-Shoup key-pair is `skb = (x1b, x2b,
y1b, y2b, zb)` and `PKb = (Cb, Db, Hb)`. Both key pairs are generated by
`DRGen()`.

#### DAKE Overview

```
Alice                                    Bob
---------------------------------------------------
Query Message or Whitespace Tag ------->
                                <------- Identity message
               DRE-Auth ------->
                                         Verify & Decrypt
```

Bob will be initiating the DAKE with Alice.

**Bob:**

1. Generates and sets `our_ecdh` as ephemeral  ECDH keys.
2. Generates and sets `our_dh` as ephemeral 3072-bit DH keys.
3. Sends Alice an Identity message.

**Alice:**

1. Receives an Identity message from Bob:
    * Validates Bob's User Profile.
    * Picks the highest compatible version of OTR listed in Bob's profile.
      If the versions are incompatible, Alice does not send any further messages.
      Version prioritization is explained [here](#version-priority).
    * Validates the received ECDH ephemeral public key is on curve 448 and sets it as `their_ecdh`.
    * Validates that the received DH ephemeral public key is on the correct group and sets it as `their_dh`.
2. Generates and sets `our_ecdh` as ephemeral ECDH keys.
3. Generates and sets `our_dh` as ephemeral 3072-bit DH keys.
4. Sends Bob a DRE-Auth message (see [DRE-Auth message section](#dre-auth-message)).
5. At this point, the DAKE is complete for Alice:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 0 (which means she will ratchet again).
    * Calculates ECDH shared secret `K_ecdh`.
    * Calculates DH shared secret `k_dh` and `mix_key`.
    * Calculates Mixed shared secret `K = SHA3-512(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: it is the first 8 bytes of `SHA3-256(0x00 || K)`.
    * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = calculate_ratchet_keys(K)`.
    * [Decides which chain key she will use](#deciding-between-chain-keys).

**Bob:**

1. Receives DRE-Auth message from Alice:
    * Validates Alice's User Profile.
    * Picks the highest compatible version of OTR listed in Alice's
      profile, and follows the specification for this version. Version
      prioritization is explained [here](#version-priority)
      If the versions are incompatible, Bob does not send any further messages.
    * Verify the authentication `sigma` (see [DRE-Auth message](#dre-auth-message)).
2. Decrypts `gamma` (see [DRE-Auth message](#dre-auth-message)) and verifies
   the following properties of the decrypted message. If any of the
   verifications fail, the message is ignored:
    * The message is of the correct form (e.g., the fields are of the expected
     length).
    * Bob's User Profile is the first one listed
    * Alice's User Profile is the second one listed, and it matches the
     one transmitted outside of the ciphertext
    * `(Y, B)` in the message is an Identity message that Bob previously sent and has not
      been used.
3. Retrieve ephemeral public keys from Alice:
    * Validates the received ECDH ephemeral public key is on curve 448 and sets it as `their_ecdh`.
    * Validates that the received DH ephemeral public key is on the correct group and sets it as `their_dh`.
4. At this point, the DAKE is complete for Bob:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 1.
    * Calculates ECDH shared secret `K_ecdh`.
    * Calculates DH shared secret `k_dh` and `mix_key`.
    * Calculates Mixed shared secret `K = SHA3-512(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: it is the first 8 bytes of `SHA3-256(0x00 || K)`.
    * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = calculate_ratchet_keys(K)`.
    * [Decides which chain key he will use](#deciding-between-chain-keys).

#### Identity message

This is the first message of the DAKE. Bob sends it to Alice to commit to a
choice of DH and ECDH key. A valid Identity message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile).
2. Generate an ephemeral ECDH key pair:
  * secret key `y`.
  * public key `Y`.
3. Generate an ephemeral DH key pair:
  * secret key `b` (80 bytes).
  * public key `B`.

An Identity message is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x0F.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For an Identity message, this will
  often be 0 since the other party may not have identified its instance tag
  yet.
Sender's User Profile (USER-PROF)
  As described in the section 'Creating a User Profile'.
Y (POINT)
  The ephemeral public ECDH key.
B (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase,
  this is NOT a POINT.
```

#### DRE-Auth message

This is the second message of the DAKE. Alice sends it to Bob to commit to a
choice of her ECDH ephemeral key and her DH ephemeral key, and acknowledgment
of Bob's ECDH ephemeral key and DH ephemeral key. This acknowledgement includes
a validation that Bob's ECDH key is on the curve 448 and his DH key is in the
correct group. The public ECDH ephemeral public keys and public DH ephemeral
public keys are encrypted with DRE and authenticated with a NIZKPK.

A valid DRE-Auth message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile)
2. Generate an ephemeral ECDH key pair:
  * secret key `x`.
  * public key `X`
3. Generate an ephemeral DH key pair:
  * secret key `a` (80 bytes).
  * public key `A`.
4. Pick random values `r` in Z_q and compute `K = G1 * r`.
5. Compute symmetric key `K_enc = SHA3-256(K)`. K is hashed from 55 bytes to 32
   bytes because XSalsa20 has a maximum key size of 32 bytes.
6. Generate `m = Bobs_User_Profile || Alices_User_Profile || Y || X || B || A`.
7. Pick a random 24 bytes `nonce` and compute `phi = XSalsa20-Poly1305_K_enc(m,
   nonce)`.
8. Compute `gamma = DREnc(PKb, PKa, K)`.
9. Compute `sigma = Auth(Ha, za, {Hb, Ha, Y}, Bobs_User_Profile || Alices_User_Profile
   || Y || B || gamma)`.

To verify and decrypt the DRE-Auth message:

1. Validate user profile.
2. Verify the `sigma` with [ROM Authentication](#rom-authentication)
   `Verify({Ha, Hb, Y}, sigma, Bobs_User_Profile || Alices_User_Profile || Y || B || gamma)`.
3. Decrypt the `gamma` with [ROM DRE](#rom-dre) `K = DRDec(PKb, PKa, skb, gamma)`.
4. Compute symmetric key `K_dec = SHA3-256(K)`.
5. Decrypt `m = XSalsa20-Poly1305_K_dec(phi, nonce)`.

A DRE-Auth is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x00.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient.
Sender's User Profile (USER-PROF)
  As described in the section 'Creating a User Profile'.
gamma (DRE-M)
  The Dual-receiver encrypted key.
sigma (AUTH)
  The Auth value.
nonce (NONCE)
  The nonce used to encrypt m.
phi (DATA)
  The encrypted message (Bobs_User_Profile || Alices_User_Profile || Y || X || B || A).
```

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange [data messages](#data-message) initialized with the
shared secret established in the DAKE. Detailed validation and processing of each data
message is described in the [section on receiving encrypted data
messages](#receiving-an-encrypted-data-message).

A message with an empty human-readable part (the plaintext is of zero length,
or starts with a NULL) is a "heartbeat" packet, and should not be displayed to
the user (but it is still useful for key rotations).

```
Alice                                                                           Bob
-----------------------------------------------------------------------------------
Initialize root key, chain keys                        Initialize root key, chain keys
Send data message 0_0            -------------------->
Send data message 0_1            -------------------->

                                                       Receive data message 0_0
                                                       Compute receiving chain key 0_0
                                                       Derive MKenc & MKmac
                                                       Verify MAC, Decrypt message 0_0

                                                       Receive data message 0_1
                                                       Compute receiving chain key 1_1
                                                       Derive MKenc & MKmac
                                                       Verify MAC, Decrypt message 0_1

                                                       Perform a new ratchet
                                 <-------------------- Send data message 1_0
                                 <-------------------- Send data message 1_1

Receive data message 1_0
Compute receiving chain key 1_0
Derive MKenc & MKmac
Verify MAC, Decrypt message 1_0

Receive data message 1_1
Recover receiving chain key 1_1
Derive MKenc & MKmac
Verify MAC, Decrypt message 1_1
```

### Data Message

This message is used to transmit a private message to the correspondent.
It is also used to [reveal old MAC keys](#revealing-mac-keys).

#### Data Message format

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
    instead of producing an error or a notification to the user.

Ratchet id (INT)
  This should be set as sender's i.

Message id (INT)
  This should be set with sender's j.

Public ECDH Key (POINT)
  This is the public part of the ECDH key used to encrypt and decrypt the
  data message. For the sender of this message, this is their
  'our_ecdh.public' value. For the receiver of this message, it is
  used as 'their_ecdh'.

Public DH Key (MPI)
  This is the public part of the DH key used to encrypt and decrypt the
  data message. For the sender of this message, it is 'our_dh.public'
  value. For the receiver of this message, it is used as 'their_dh'. If
  this value is empty, its length is zero.

Nonce (NONCE)
  The nonce used with XSalsa20 to create the encrypted message contained
  in this packet.

Encrypted message (DATA)
  Using the appropriate encryption key (see below) derived from the
  sender's and recipient's DH public keys (with the keyids given in this
  message), perform XSalsa20 encryption of the message. The nonce used for
  this operation is also included in the header of the data message
  packet.

Authenticator (MAC)
  The SHA3 MAC with the appropriate MAC key (see below) for everything:
  from the protocol version to the end of the encrypted message.

Old MAC keys to be revealed (DATA)
  See Revealing MAC Keys section
```

#### When you send a Data Message:

In order to send a data message, a key is required to encrypt it. This key
will be derived from the previous chain key and, if the message's counter `j`
has been set to `0`, keys should be rotated.

Given a new ratchet:

  * Rotate the ECDH keys and mix key, see "Rotating ECDH keys and mix key" section.
    The new ECDH public key created by the sender with this process will be the
    "Public ECDH Key" for the message. If a new public DH key is created in
    this process, it will be the "Public DH Key" for the message. If it is
    not created, then it will be empty.
  * Calculate the `K = SHA3-512(K_ecdh || mix_key)`.
  * Derive new set of keys `root[i], chain_s[i][0], chain_r[i][0] = calculate_ratchet_keys(K)`.
  * Securely delete the root key and all chain keys from the ratchet `i-2`.
  * Securely delete `K`.

Otherwise:

  * Increment current sending message ID `j = j+1`.
  * Derive the next sending chain key `derive_chain_key(chain_s, i, j)`.
  * Securely delete `chain_s[i][j-1]`.

In both cases:

  * Calculate the encryption key (`MKenc`) and the mac key (`MKmac`):

   ```
   MKenc, MKmac = derive_enc_mac_keys(chain_s[i][j])
   ```

  * Get a random 24 bytes value to be the `nonce`.
  * Use the encryption key to encrypt the message and the mac key to calculate
    its MAC:

   ```
   Encrypted_message = XSalsa20_Enc(MKenc, nonce, m)
   ```

  * Use the MAC key to create a MAC tag. MAC all the sections of the data message
    from the protocol version to the encrypted message.

   ```
   Authenticator = SHA3-512(MKmac || Data_message_sections)
   ```

  * Forget and reveal MAC keys. The conditions for revealing MAC keys is
    stated in the [Revealing MAC keys](#revealing-mac-keys) section.

#### When you receive a Data Message:

* Use the `message_id` to compute the receiving chain key, and calculate
encryption and mac keys.

  ```
    compute_chain_key(chain_r, ratchet_id, message_id)
    MKenc, MKmac = derive_enc_mac_keys(chain_r[ratchet_id][message_id])
  ```

* Use the "mac key" (`MKmac`) to verify the MAC of the message. If the message
  verification fails, reject the message.

Otherwise:

  * Decrypt the message using the "encryption key" (`MKenc`) and securely
    delete it.
  * Securely delete receiving chain keys older than `message_id-1`.
  * Set `j = 0` to indicate that a new DH-ratchet should happen the next time
    you send a message.
  * Set `their_ecdh` as the "Public ECDH key" from the message.
  * Set `their_dh` as the "Public DH Key" from the message, if it
    is not NULL.
  * Add the MKmac key to list `mac_keys_to_reveal`.

### Revealing MAC Keys

We reveal old MAC keys to provide [forgeability of messages](#forging-transcripts).
Old MAC keys are keys for already received messages and, therefore, will no
longer be used to verify the authenticity of the message.

Data messages and heartbeat messages (data messages with a plaintext length of
zero) reveal MAC keys. If a participant has not sent a data message in some
configurable amount of time, a heartbeat message is sent to reveal the MAC keys.

Old MAC keys are formatted as a list of concatenated 64 byte values.

A MAC key is added to `mac_keys_to_reveal` after a participant has verified
a message associated with the MAC key or after they have discarded the
encryption key associated with the MAC key.

## Fragmentation

Some networks may have a `maximum message size` that is too small to contain
an encoded OTR message. In that event, the sender may choose to split the
message into a number of fragments. This section describes the format for the
fragments.

OTRv4 has the same message fragmentation as OTRv3, without compatibility with
OTRv2. This means that OTRv4 and OTRv3 perform fragmentation in the same way,
with the same format. Thus, message parsing should happen after the message has
been reassembled.

All OTRv4 clients must be able to assemble received fragments, but performing
fragmentation on outgoing messages is optional.

### Transmitting Fragments

If you have information about the `maximum message size` you are able to send
(different IM networks have different limits), you can fragment an encoded
OTR message as follows:

  * Start with the OTR message as you would normally transmit it. For example,
    a Data Message would start with `?OTR:AAQD` and end with `.`.
  * Break it up into sufficiently small pieces. Let this number of pieces be
  `total`, and the pieces be `piece[1],piece[2],...,piece[total]`.
  * Transmit `total` OTRv4 fragmented messages with the following structure:

  ```
  ?OTR|sender_instance|receiver_instance,index,total,piece[index],
  ```

The message should begin with `?OTR|` and end with `,`.

Note that `index` and `total` are unsigned short ints (2 bytes), and each has
a maximum value of 65535. Also, each `piece[index]` must be non-empty.
The instance tags, `index` and `total` values may have leading zeros.

Note that fragments are not messages that can be fragmented: you can't fragment a fragment.

### Receiving Fragments:

If you receive a message containing `?OTR|` (note that you'll need to check
for this _before_ checking for any of the other `?OTR:` markers):

  * Parse it, extracting instance tags, `index`, `total`, and `piece[index]`.
  * Discard illegal fragment, if:
       * the recipient's own instance tag does not match the listed receiver
       instance tag
       * and the listed receiver instance tag is not zero,
    * then, discard the message and optionally pass a warning to the user.
    * `index` is 0
    * `total` is 0
    * `index` is bigger than total

  * If this is the first fragment:
    * Forget any stored fragment you may have
    * Store `piece`
    * Store `index` and `total`

  * If this is the following fragment (same stored `total` and `index==index+1`):
    * Append `piece` to stored `piece`
    * Store `index` and `total`

  * Otherwise:
    * Forget any stored fragment you may have
    * Forget stored `piece`
    * Forget stored `index` and `total`

After this, if stored `total` is bigger than 0 and stored `index` is equal to
stored `total`, treat `piece` as the received message.

If you receive a non-OTR message or an unfragmented message, forget any
stored value you may have (`piece`, `total` and, `index`).

For example, here is a Data Message we would like to transmit over a network
with an unreasonably small `maximum message size`:

    ?OTR:AAQD--here-is-my-very-long-message

We could fragment this message into three pieces:

    ?OTR|5a73a599|27e31597,00001,00003,?OTR:AAQD--here,
    ?OTR|5a73a599|27e31597,00002,00003,is-my-very-long,
    ?OTR|5a73a599|27e31597,00003,00003,-message,

## The protocol state machine

An OTR client maintains separate state for every correspondent. For example,
Alice may have an active OTR conversation with Bob, while having an insecure
conversation with Charlie.

The way the client reacts to user input and to received messages depends on
whether the client has decided to allow version 3 and/or 4, if encryption is
required and if it will advertise OTR support.

### Protocol states

```
START

  This is the state that is used before an OTR conversation is initiated.
  The initial state, and the only way to subsequently enter this state is for
  the user to explicitly request to do so via some UI operation. Messages
  sent in this state are plaintext messages. If a TLV type 1 (Disconnect)
  message is sent in another state, transition to this state.

DAKE_IN_PROGRESS

  This state is entered when a participant receives or sends an Identity
  message. Data Messages created in this state are queued for delivery in the
  next ENCRYPTED_MESSAGES state.

ENCRYPTED_MESSAGES

  This state is entered after DRE-Auth message has been sent or it has been
  received and validated. Messages sent in this state are encrypted.

FINISHED

  This state is entered only when a participant receives a TLV type 1
  (Disconnected) message, which indicates they have terminated their side
  of the OTR conversation. For example, if Alice and Bob are having an OTR
  conversation, and Bob instructs his OTR client to end its private session
  with Alice (for example, by logging out), Alice will be notified of this,
  and her client will switch to FINISHED mode. This prevents  Alice from
  accidentally sending a message to Bob in plaintext (consider what happens
  if Alice was in the middle of typing a private message to Bob when he
  suddenly logs out, just as Alice hits Enter.)
```

### Protocol events

The following sections will outline the actions that the protocol should
implement.

Note:

* The receiving instance tag must be specified and should match the
  instance tag the client uses to identify itself. Otherwise, the
  message should be discarded and the user optionally warned. Nevertheless D-H
  Commit and Identity messages may not specify the receiver's instance tag. In
  this case the value is set to zero.
* The protocol is initialized with the allowed versions (3 and/or 4).

#### User requests to start an OTR conversation

Send an OTR Query Message or a plaintext message with a whitespace
tag to the correspondent. [Query messages](#query-messages) and [whitespace
tags](#whitespace-tags) are constructed according to the sections below.

##### Query Messages

If Alice wishes to communicate to Bob that she would like to use OTR,
she sends a message containing the string "?OTRv" followed by an indication of
what versions of OTR she is willing to use with Bob. The version string is
constructed as follows:

If she is willing to use OTR version 3, she appends a byte identifier for the
versions in question, followed by "?". The byte identifier for OTR version 3
is "3", and similarly for 4. Thus, if she is willing to use OTR versions 3 and 4,
the following identifier would be "34". The order of the identifiers between the
"v" and the "?" does not matter, but none should be listed more than once. The OTRv4
specification only supports versions 3 and higher. Thus, query messages for
older versions have been omitted.

Example query messages:

"?OTRv3?"
    Version 3
"?OTRv45x?"
    Version 4, and hypothetical future versions identified by "5" and "x"
"?OTRv?"
    A bizarre claim that Alice would like to start an OTR conversation, but is
    unwilling to speak any version of the protocol. Although this is
    syntactically valid, the receiver will not create a reply.

These strings may be hidden from the user (for example, in an attribute of an
HTML tag), and may be accompanied by an explanatory message ("Alice has
requested an Off-the-Record private conversation."). If Bob is willing to use
OTR with Alice (with a protocol version that Alice has offered), he should start
the AKE according to the highest compatible version he supports.

##### Whitespace Tags

If Alice wishes to communicate to Bob that she is willing to use OTR, she can attach
a special whitespace tag to any plaintext message she sends him. This tag may occur
anywhere in the message, and may be hidden from the user (as in the [Query
Messages](#query-messages), above).

The tag consists of the following 16 bytes, followed by one or more sets of 8 bytes
indicating the version of OTR Alice is willing to use:

  Always send "\x20\x09\x20\x20\x09\x09\x09\x09" "\x20\x09\x20\x09\x20\x09\x20\x20", followed by one or more of:
  "\x20\x20\x09\x09\x20\x20\x09\x09" to indicate a willingness to use OTR version 3 with Bob
  "\x20\x20\x09\x09\x20\x09\x20\x20" to indicate a willingness to use OTR version 4 with Bob

If Bob is willing to use OTR with Alice (with a protocol version that Alice has offered),
he should start the AKE. On the other hand, if Alice receives a plaintext message from Bob
(rather than an initiation of the AKE), she should stop sending him the whitespace tag.

#### Receiving plaintext without the whitespace tag

Display the message to the user.

If the state is `ENCRYPTED_MESSAGES`, `DAKE_IN_PROGRESS`, or `FINISHED`:

  * The user should be warned that the message received was unencrypted.

#### Receiving plaintext with the whitespace tag

Remove the whitespace tag and display the message to the user.

If the tag offers OTR version 4 and version 4 is allowed:

  * Send an Identity message.
  * Transition the state to `DAKE_IN_PROGRESS`.

If the tag offers OTR version 3 and version 3 is allowed:

  * Send a version 3 D-H Commit Message.
  * Proceed with the protocol as specified in OTRv3 "Receiving plaintext with
    the whitespace tag" [\[7\]](#references).

#### Receiving a Query Message

If the Query Message offers OTR version 4 and version 4 is allowed:

  * Send an Identity message.
  * Transition the state to `DAKE_IN_PROGRESS`.

If the Query message offers OTR version 3 and version 3 is allowed:

  * Send a version 3 D-H Commit Message.
  * Proceed with the protocol as specified in OTRv3 "Receiving a Query Message"
    [\[7\]](#references).

#### Receiving OTRv3 Specific Messages

Whether the message is an AKE message or a Data message, proceed as specified in OTRv3.
See "The protocol state machine" section [\[7\]](#references).

#### Receiving an Identity message

If the state is `START`:

  * Validate the Identity message. If any of the verifications fail, ignore the
    message.
    * Verify that the user profile signature is valid.
    * Verify that the user profile is not expired.
    * Verify that your versions are compatible with the versions in the user
      profile.
      * If your versions are incompatible with the versions in the message,
        ignore the message
      * Else, pick the highest compatible version and follow the OTR
        specification for this version. Version prioritization is detailed
        [here](#version-prioritizing).
    * If the highest compatible version is OTR version 4
      * Verify that the point `Y` received is on curve 448.
      * Verify that the DH public key `B` is from the correct group.
      * If all validations succeed:
          * send a DRE-Auth message
          * transition to the `ENCRYPTED_MESSAGES` state.

If the state is `DAKE_IN_PROGRESS`:

This indicates that both you and the other participant have sent Identity
messages to each other. This can happen if they send you an Identity message
before receiving yours.

To agree on an Identity message to use for this conversation:

  * Compare the `X` (as a 56-byte unsigned big-endian value) you sent in you
    Identity message with the value from the message you received.
  * If yours is the lower hash value:
    * Ignore the received Identity message.
  * Otherwise:
    * Forget your old `X` value that you sent earlier.
    * Validate the Identity message. If any of the verifications fail, ignore the
      message.
      * Verify that the user profile signature is valid.
      * Verify that the user profile is not expired.
      * Verify that your versions are compatible with the versions in the user
        profile.
        * If your versions are incompatible with the versions in the message,
          ignore the message
        * Else, pick the highest compatible version and follow the OTR
          specification for this version. Version prioritization is detailed
          [here](#version-prioritizing).
    * If the highest compatible version is OTR version 4
      * Verify that the point `Y` received is on curve 448.
      * Verify that the DH public key `B` is from the correct group.
      * If validation succeeds:
        * Send a DRE-Auth message.
        * Transition to the `ENCRYPTED_MESSAGES` state.

If the state is `ENCRYPTED_MESSAGES`:

  * Validate the Identity message. If any of the verifications fail, ignore the
    message.
    * Verify that the user profile signature is valid.
    * Verify that the user profile is not expired.
    * Verify that your versions are compatible with the versions in the user
      profile.
      * If your versions are incompatible with the versions in the message,
        ignore the message
      * Else, pick the highest compatible version and follow the OTR
        specification for this version. Version prioritization is detailed
        [here](#version-prioritizing).
    * If the highest compatible version is OTR version 4
      * Verify that the point `Y` received is on curve 448.
      * Verify that the DH public key `B` is from the correct group.
      * If all validations succeed:
          * send a DRE-Auth message
          * stay in the `ENCRYPTED_MESSAGES` state.

#### Sending a DRE-Auth message

* Compute the ECDH shared secret `K_ecdh`.
* Compute the mix key `mix_key`.
* Transition the state to `ENCRYPTED_MESSAGES`.
* Initialize the double ratcheting.
* Send a DRE-Auth Message.

#### Receiving a DRE-Auth message

If the state is not `DAKE_IN_PROGRESS`:

  * Ignore this message.

If the state is `DAKE_IN_PROGRESS`:

  * Verify that the Sender's User Profile. If any of the verifications fail, ignore the
    message.
    * Check that the profile is not expired
    * Pick the highest compatible version indicated in the profile.
      * If the versions advertised are not compatible with those that are supported,
        ignore this message.
      * Else, follow the specification for the highest compatible version.
        Version prioritization is detailed [here](#version-priority)
      * If the highest compatible version is version 4:
        * If the auth `sigma` is valid:
          * Decrypt the DRE key.
          * Decrypt phi and verify:
            * that our profile is the first in the message.
            * that their user profile is not expired and matches the profile
              in the Sender's User Profile section.
            * that the point `X` received is on curve 448.
            * that the DH public key `A` is from the correct group.
            * that `Y` and `B` were previously sent in this session (and remain unused).
            * If everything verifies:
              * Compute the ECDH shared secret `K_ecdh`.
              * Compute the mix key `mix_key`.
              * Initialize the double ratcheting.
              * Transition state to `ENCRYPTED_MESSAGES`.

#### Sending an encrypted data message

The `ENCRYPTED_MESSAGES` state is the only state where a participant is allowed
to send encrypted data messages.

If the state is `START` or `DAKE_IN_PROGRESS`, queue the message for encrypting
and sending when the participant transitions to the `ENCRYPTED_MESSAGES` state.

If the state is `FINISHED`, the participant must start another OTR conversation
to send encrypted messages.

#### Receiving an encrypted data message

If the state is not `ENCRYPTED_MESSAGES`:

  * Inform the user that an unreadable encrypted message was received.
  * Reply with an Error Message with ERROR_CODE_1.

Otherwise:

  * To validate the data message:
    * Verify the MAC tag.
    * Check if the message version is allowed.
    * Verify that the instance tags are consistent with those used in the DAKE.
    * Verify that the public ECDH key is on curve 448.
    * Verify that the public DH key is from the correct group.

  * If the message is not valid in any of the above steps, discard it and
    optionally pass along a warning to the user.

  * Use the ratchet id and the message id to compute the corresponding
    decryption key. Try to decrypt the message.

    * If the message cannot be decrypted and the `IGNORE_UNREADABLE` flag is not
    set:
      * Inform the user that an unreadable encrypted message was received.
      * Reply with an Error Message with ERROR_CODE_1.

    * If the message cannot be decrypted and the `IGNORE_UNREADABLE` flag is
    set:
      * Ignore it instead of producing an error or a notification to the user.

    * If the message can be decrypted:
      * Display the human-readable part (if it contains any) to the user. SMP
      TLVs should be addressed according to the SMP state machine.
      * Rotate root, chain and mix keys as appropriate.
      * If the received message contains a TLV type 1 (Disconnected) [\[7\]](#references)
        forget all encryption keys for this correspondent and transition the
        state to `FINISHED`.

   * If you have not sent a message to this correspondent in some
     (configurable) time, send a "heartbeat" message.

#### Receiving an Error Message

* Detect if an error code exists in the form "ERROR_CODE_x" where x is a number.
* Display the human-readable error message to the user. If an error code exists,
* Display the message in the user configured language.

#### User requests to end an OTR conversation

Send a data message, encoding a message with an empty human-readable part, and
TLV type 1. Transition to the `START` state.

#### Receiving a TLV type 1 (Disconnect) Message

If a TLV type 1 is received in the `START` state, stay in that state, else
transition to the START state and [reset the state variables and key
variables](#resetting-state-and-key-variables).

## Socialist Millionaires Protocol (SMP)

SMP in version 4 shares the same TLVs and flow as SMP in OTRv3 with the
following exceptions.

In OTRv3, SMP Message 1 is used when a user does not specify an SMP question
and, if not, a SMP Message 1Q is used. OTRv4 is simplified to use only SMP
Message 1 for both cases. When a question is not present, the user specified
question section has length 0 and value NULL.

OTRv4 creates fingerprints using SHA3-512, which increases their size. Thus,
the size of the fingerprint in the "Secret Information" section of OTRv3 [\[7\]](#references)
should be 64 bytes in size.

Lastly, OTRv4 uses Ed448 as the cryptographic primitive. This changes the way
values are serialized and how they are computed. To define the SMP values
under Ed448, we reuse the previously defined G1 generator for Cramer-Shoup:

```
G1 = (11781216126343694673728248434331006466518053535701637341687908214793940427
7809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf3932
d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)
```

### SMP Overview

Assuming that Alice begins the exchange:

**Alice:**

* Picks random values `a2` and `a3` in `Z_q`.
* Picks random values `r2` and `r3` in `Z_q`.
* Computes `c2 = HashToScalar(1 || G1 * r2)` and `d2 = r2 - a2 * c2`.
* Computes `c3 = HashToScalar(2 || G1 * r3)` and `d3 = r3 - a3 * c3`.
* Sends Bob a SMP message 1 with `G2a = G1 * a2`, `c2`, `d2`, `G3a = G1 * a3`, `c3`
  and `d3`.

**Bob:**

* Validates that `G2a` and `G3a` are on the curve 448.
* Picks random values `b2` and `b3` in `Z_q`.
* Picks random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`.
* Computes `G2b = G1 * b2` and `G3b = G1 * b3`.
* Computes `c2 = HashToScalar(3 || G1 * r2)` and `d2 = r2 - b2 * c2`.
* Computes `c3 = HashToScalar(4 || G1 * r3)` and `d3 = r3 - b3 * c3`.
* Computes `G2 = G2a * b2` and `G3 = G3a * b3`.
* Computes `Pb = G3 * r4` and `Qb = G1 * r4 + G2 * y`, where y is the 'actual secret'.
* Computes `cp = HashToScalar(5 || G3 * r5 || G1 * r5 + G2 * r6)`, `d5 = r5 - r4 * cp`
  and `d6 = r6 - y * cp`.
* Sends Alice a SMP message 2 with `G2b`, `c2`, `d2`, `G3b`, `c3`, `d3`, `Pb`,
  `Qb`, `cp`, `d5` and `d6`.

**Alice:**

* Validates that `G2b` and `G3b` are on the curve 448.
* Computes `G2 = G2b * a2` and `G3 = G3b * a3`.
* Picks random values `r4`, `r5`, `r6` and `r7` in `Z_q`.
* Computes `Pa = G3 * r4` and `Qa = G1 * r4 + G2 * x`, where x is the 'actual secret'.
* Computes `cp = HashToScalar(6 || G3 * r5 || G1 * r5 + G2 * r6)`, `d5 = r5 - r4 * cp`
  and `d6 = r6 - x * cp`.
* Computes `Ra = (Qa - Qb) * a3`.
* Computes `cr = HashToScalar(7 || G1 * r7 || (Qa - Qb) * r7)` and `d7 = r7 - a3 * cr`.
* Sends Bob a SMP message 3 with `Pa`, `Qa`, `cp`, `d5`, `d6`, `Ra`, `cr` and `d7`.

**Bob:**

* Validates that `Pa`, `Qa`, and `Ra` are on the curve 448.
* Picks a random value `r7` in `Z_q`.
* Computes `Rb = (Qa - Qb) * b3`.
* Computes `Rab = Ra * b3`.
* Computes `cr = HashToScalar(8 || G1 * r7 || (Qa - Qb) * r7)` and `d7 = r7 - b3 * cr`.
* Checks whether `Rab == Pa - Pb`.
* Sends Alice a SMP message 4 with `Rb`, `cr`, `d7`.

**Alice:**

* Validates that `Rb` is on curve 448.
* Computes `Rab = Rb * a3`.
* Checks whether `Rab == Pa - Pb`.

If everything is done correctly, then `Rab` should hold the value of
`(Pa - Pb) * ((G2 * a3 * b3) * (x - y))`, which means that the test at the end of the
protocol will only succeed if `x == y`. Further, since `G2 * a3 * b3` is a random
number not known to any party, if `x` is not equal to `y`, no other information
is revealed.

### Secret information

The secret information x and y compared during this protocol contains not only
information entered by the users, but also information unique to the
conversation in which SMP takes place. Specifically, the format is:

```
Version (BYTE)
  The version of SMP used. The version described here is 1.
Initiator fingerprint (64 BYTE)
  The fingerprint that the party initiating SMP is using in the current
  conversation.
Responder fingerprint (64 BYTE)
  The fingerprint that the party that did not initiate SMP is using in the
  current conversation.
Secure Session ID
  The ssid described previously.
User-specified secret
  The input string given by the user at runtime.
```

Then the SHA3-512 hash of the above is taken, and the digest becomes the
actual secret (x or y) to be used in SMP. The additional fields insure that
not only do both parties know the same secret input string, but no man-in-the-
middle is capable of reading their communication either.

### SMP Hash function

In the following actions, there are many places where a SHA3-512 hash of an
integer followed by one or two MPIs is taken. This is defined as `HashToScalar(d)`.

The input to this hash function is:

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

### SMP message 1

Alice sends SMP message 1 to begin a DH exchange to determine two new
generators, `g2` and `g3`. A valid SMP message 1 is generated as follows:

1. Determine her secret input `x`, which is to be compared to Bob's secret
   `y`, as specified in the "Secret Information" section.
2. Pick random values `a2` and `a3` in `Z_q`. These will be Alice's
exponents for the DH exchange to pick generators.
3. Pick random values `r2` and `r3` in `Z_q`. These will be used to
generate zero-knowledge proofs that this message was created according to the
protocol.
4. Compute `G2a = G * a2` and `G3a = G * a3`.
5. Generate a zero-knowledge proof that the value `a2` is known by setting
`c2 = HashToScalar(1 || G * r2)` and `d2 = r2 - a2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value `a3` is known by setting
`c3 = HashToScalar(2 || G * r3)` and `d3 = r3 - a3 * c3 mod q`.
7. Store the values of `x`, `a2` and `a3` for use later in the protocol.


The SMP message 1 has the following data:

```
question (DATA)
  A user-specified question, which is associated with the user-specified portion
  of the secret.
  If there is no question input from the user, the length of this is 0 and the
  data is NULL.

G2a (POINT)
  Alice's half of the DH exchange to determine G2.

c2 (MPI), d2 (MPI)
  A zero-knowledge proof that Alice knows the value associated with her
  transmitted value G2a.

G3a (POINT)
  Alice's half of the DH exchange to determine G3.

c3 (MPI), d3 (MPI)
  A zero-knowledge proof that Alice knows the value associated with her
  transmitted value G3a.

```

### SMP message 2

SMP message 2 is sent by Bob to complete the DH exchange to determine the new
generators, g2 and g3. It also begins the construction of the values used in
the final comparison of the protocol. A valid SMP message 2 is generated as
follows:

1. Validate that `G2a` and `G3a` are on curve 448.
2. Determine Bob's secret input `y`, which is to be compared to Alice's secret
   `x`.
3. Pick random values `b2` and `b3` in `Z_q`. These will used during
   the DH exchange to pick generators.
4. Pick random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`. These
   will be used to add a blinding factor to the final results, and to generate
   zero-knowledge proofs that this message was created honestly.
5. Compute `G2b = G * b2` and `G3b = G * b3`.
6. Generate a zero-knowledge proof that the value `b2` is known by setting
`c2 = HashToScalar(3 || G * r2)` and `d2 = r2 - b2 * c2 mod q`.
7. Generate a zero-knowledge proof that the value `b3` is known by setting
`c3 = HashToScalar(4 || G * r3)` and `d3 = r3 - b3 * c3 mod q`.
8. Compute `G2 = G2a * b2` and `G3 = G3a * b3`.
9. Compute `Pb = G3 * r4` and `Qb = G * r4 + G2 * y`.
10. Generate a zero-knowledge proof that `Pb` and `Qb` were created according
   to the protocol by setting `cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6)`,
   `d5 = r5 - r4 * cp mod q` and `d6 = r6 - y * cp mod q`.
11. Store the values of `G3a`, `G2`, `G3`, `b3`, `Pb` and `Qb` for use later
    in the protocol.


The SMP message 2 has the following data:

```
G2b (POINT)
  Bob's half of the DH exchange to determine G2.

c2 (MPI), d2 (MPI)
  A zero-knowledge proof that Bob knows the exponent associated with his
  transmitted value G2b.

G3b (POINT)
  Bob's half of the DH exchange to determine G3.

c3 (MPI), d3 (MPI)
  A zero-knowledge proof that Bob knows the exponent associated with his
  transmitted value G3b.

Pb (POINT), Qb (POINT)
  These values are used in the final comparison to determine if Alice and Bob
  share the same secret.

cp (MPI), d5 (MPI), d6 (MPI)
  A zero-knowledge proof that Pb and Qb were created according to the protocol
  given above.
```

### SMP message 3

SMP message 3 is Alice's final message in the SMP exchange. It has the last of
the information required by Bob to determine if `x = y`. A valid SMP message 1
is generated as follows:

1. Validate that `G2b`, `G3b`, `Pb`, and `Qb` are on curve 448.
2. Pick random values `r4`, `r5`, `r6` and `r7` in `Z_q`. These will
   be used to add a blinding factor to the final results, and to generate
   zero-knowledge proofs that this message was created honestly.
3. Compute `G2 = G2b * a2` and `G3 = G3b * a3`.
4. Compute `Pa = G3 * r4` and `Qa = G * r4 + G2 * x`.
5. Generate a zero-knowledge proof that `Pa` and `Qa` were created according to
   the protocol by setting `cp = HashToScalar(6 || G3 * r5 || G1 * r5 + G2 * r6)`,
   `d5 = r5 - r4 * cp mod q` and `d6 = r6 - x * cp mod q`.
6. Compute `Ra = (Qa - Qb) * a3`.
7. Generate a zero-knowledge proof that `Ra` was created according to the
   protocol by setting `cr = HashToScalar(7 || G1 * r7 || (Qa - Qb) * r7)` and
   `d7 = r7 - a3 * cr mod q`.
8. Store the values of `G3b`, `Pa - Pb`, `Qa - Qb` and `Ra` for use later in
   the protocol.

The SMP message 3 has the following data:

```
Pa (POINT), Qa (POINT)
  These values are used in the final comparison to determine if Alice and Bob
  share the same secret.

cp (MPI), d5 (MPI), d6 (MPI)
  A zero-knowledge proof that Pa and Qa were created according to the protocol
  given above.

Ra (POINT)
  This value is used in the final comparison to determine if Alice and Bob
  share the same secret.

cr (MPI), d7 (MPI)
  A zero-knowledge proof that Ra was created according to the protocol given
  above.
```

### SMP message 4

SMP message 4 is Bob's final message in the SMP exchange. It has the last of
the information required by Alice to determine if `x = y`. A valid SMP message
4 is generated as follows:

1. Validate that `Pa`, `Qa`, and `Ra` are on curve 448.
2. Pick a random value `r7` in `Z_q`. This will be used to generate
Bob's final zero-knowledge proof that this message was created honestly.
3. Compute `Rb = (Qa - Qb) * b3`.
4. Generate a zero-knowledge proof that `Rb` was created according to the protocol by setting
	`cr = HashToScalar(8 || G1 * r7 || (Qa - Qb) * r7)` and `d7 = r7 - b3 * cr mod q`.

The SMP message 4 has the following data:

```
Rb (POINT)
  This value is used in the final comparison to determine if Alice and Bob
  share the same secret.

cr (MPI), d7 (MPI)
  A zero-knowledge proof that Rb was created according to the protocol given
  above.
```

### The SMP state machine

OTRv4 does not change the state machine for SMP. But the following sections
detail how values are computed differently during some states.

#### Receiving a SMP message 1

If smpstate is not `SMPSTATE_EXPECT1`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Alice.

If smpstate is `SMPSTATE_EXPECT1`:

* Verify Alice's zero-knowledge proofs for G2a and G3a:
  1. Check that both `G2a` and `G3a` are points in the curve.
  2. Check that `c2 = HashToScalar(1 || G1 * d2 + G2a * c2)`.
  3. Check that `c3 = HashToScalar(2 || G1 * d3 + G3a * c3)`.
* Create a SMP message 2 and send it to Alice.
* Set smpstate to `SMPSTATE_EXPECT3`.

#### Receiving a SMP message 2

If smpstate is not `SMPSTATE_EXPECT2`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT2`:

* Verify Bob's zero-knowledge proofs for `G2b`, `G3b`, `Pb` and `Qb`:
    1. Check that `G2b`, `G3b`, `Pb` and `Qb` are points in the curve.
    2. Check that `c2 = HashToScalar(3 || G1 * d2 + G2b * c2)`.
    3. Check that `c3 = HashToScalar(4 || G1 * d3 + G3b * c3)`.
    4. Check that `cp = HashToScalar(5 || G3 * d5 + Pb * cp || G * d5 + G2 * d6 + Qb * cp)`.
* Create SMP message 3 and send it to Bob.
* Set smpstate to `SMPSTATE_EXPECT4`.

#### Receiving a SMP message 3

If smpstate is not `SMPSTATE_EXPECT3`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT3`:

* Verify Alice's zero-knowledge proofs for `Pa`, `Qa` and `Ra`:
  1. Check that `Pa`, `Qa` and `Ra` are points in the curve.
  2. Check that `cp = HashToScalar(6 || G3 * d5 + Pa * cp || G1 * d5 + G2 * d6 +
     Qa * cp)`.
  3. Check that `cr = HashToScalar(7 || G1 * d7 + G3a * cr || (Qa - Qb) * d7 +
     Ra * cr)`.
* Create a SMP message 4 and send it to Alice.
* Check whether the protocol was successful:
  1. Compute `Rab = Ra * b3`.
  2. Determine if `x = y` by checking the equivalent condition that
     `Pa - Pb = Rab`.
* Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from
  Alice.

  //`cr = HashToScalar(8 || G1 * r7 || (Qa - Qb) * r7)` and `d7 = r7 - b3 * cr mod q`.

#### Receiving a SMP message 4

If smpstate is not `SMPSTATE_EXPECT4`:
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is SMPSTATE_EXPECT4:

* Verify Bob's zero-knowledge proof for Rb:
   1. Check that `Rb` is a point on the curve.
   2. Check that `Rb` is `>= 2` and `<= modulus-2`.
   3. Check that `cr = HashToScalar(8 || G1 * d7 + G3 * cr || (Qa / Qb) * d7 + Rb * cr)`.

* Check whether the protocol was successful:
    1. `Compute Rab = Rb * a3`.
    2. Determine if `x = y` by checking the equivalent condition that
       `(Pa / Pb) = Rab`.

Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected
from Bob.

## Implementation Notes

### Considerations for networks that allow multiple devices

When using a transport network that allows multiple devices to be simultaneously
logged in with the same peer identifier, make sure to identify the other
participant by its device-specific identifier and not only the peer identifier
(for example, using XMPP full JID instead of bare JID). Doing so allows
establishing an OTR channel at the same time with multiple devices from the
other participant at the cost of how to expose this to the message client (for
example, XMPP clients can decide to reply only to the device you have more
recently received a message from).

## Forging Transcripts

OTRv4 strongly encourages that each implementation of this specification exposes
an interface for producing forged transcripts with the same functions used to
conduct honest conversations. This section will guide implementers through
achieving this. The major utilities are:

Parse
  Parses OTR messages given as input to show the values of each of the fields in
  a message. Parse will reuse the message parsing functionality of the spec.

Modify Data Message
  Even if an encrypted data message cannot be read because we don't
  know the message key (or a key used to derive this message key), if a good
  guess can be made that the string `x` appears at a given offset in the message,
  this method will replace the old text with some new desired text, which
  must be the same length. For example, if the string "hi" is accurately guessed
  to be at the beginning of an encrypted message, it can be replaced with "yo",
  and a cryptographically valid data message can be created with the new text.

  To achieve this, the XOR of the old text and the new text is XORed
  again with the original encrypted message starting at the given offset.
  After replacing parts of the encrypted message, the MAC tag is recalculated
  with the revealed MAC key associated with this message number. Then the
  new tag is attached to the data message, replacing the old value. A pseudocode
  [example](#modify-an-encrypted-data-message) is included in the appendix.

  This modification works because the encryption that the data message relies
  up on is malleable.

  Modify Data Message reuses the [MAC tag creation](#when-you-send-a-data-message)
  functionality of the spec.

Read and Forge
  Read and forge allows someone in possession of a chain key to decrypt OTR messages
  or modify them as forgeries. It takes three inputs, the chain key, the OTR
  message and an optional new plain text message. If the new message is included,
  the original text is replaced with the new message, and then a new MAC tag,
  based on the new message is attached to the data message. This new message is
  then displayed. One applicable scenario is a participant listening and forging
  the messages as the revealed MAC keys are received.

  Read and Forge reuses the message parser, [decrypt a data
  message],(#receiving-an-encrypted-data-message) and [MAC tag
  creation](#when-you-send-a-data-message) functionalities of the spec.

Forge AKE and Session Keys
  Any participant of an OTR conversation may forge an AKE with another participant
  as long as they have their profile. This function will take the profile and secret
  long term key of one participant and the profile of another. It will return
  an AKE transcript between the two parties. The participant's private key is
  required since it is used to authenticate the key exchange, but the resulting
  transcript is created in such a way that a cryptographic expert cannot identify
  which profile owner authenticated the conversation.

  This forging utility reuses the spec functions:
    1. [Create a Identity message](#identity-message)
    2. [Create a DRE-Auth message](#dre-auth-message)

Forge Entire Transcript
  The Forge Entire Transcript function will allow one participant to completely
  forge a transcript between them and another person in a way that its forgery cannot be
  cryptographically proven. The input will be one participant's profile, their secret
  key, another person's profile, and a list of plain text messages corresponding to
  what messages were exchanged. Each message in the list will have the structure:
  1) sender 2) plain text message, so that the function may precisely create the
  desired transcript. The participant's private key is required since it is used
  to authenticate the key exchange, but the resulting transcript is created in such a
  way that a cryptographic expert cannot identify which profile owner authenticated
  the conversation.

  This forging utility reuses the spec functions:
    1. [Create an Identity message](#identity-message)
    2. [Create a DRE-Auth message](#dre-auth-message)
    3. [Create an encrypted data message](#data-exchange)
    4. [The protocol state machine](#the-protocol-state-machine)

## Appendices

### ROM DRE

The DRE scheme consists of three functions:

`PK, sk = DRGen()`, a key generation function.

`gamma = DREnc(PK1, PK2, K)`, an encryption function.

`K = DRDec(PK1, PK2, ski, gamma) i ∈ {1, 2}` , a decryption function.

#### Domain parameters

The Cramer-Shoup scheme uses a group (`G`, `q`, `G1`, `G2`). This is a group
with the same `q` as Curve 448. The generators `G1` and `G2` are:

```
G1 = (1178121612634369467372824843433100646651805353570163734168790821479394042
77809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf393
2d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)

G2 = (16198104581588018595899223143190272311918511238122751222361431851896743243
4013519584102297147218387513217725422122524316513263204161236914142188,
17443011591827011924522432141214711554174683032038520272613022239901295213216602
00204217838721145102661825010820238188238915121131226223
)

=(0xa162683a9e50b9093a63df8fbe1be7bf5570267a4b7aec8fb9bd432bf32887c3540ae5472fda
264b84b1fedde1f3a5843fcca117450e8ebc,
0xae2b000b3bb64677f5e0208d02937336ae441e03cb55141b1a8216ef5a8105d5d83cc8ccd95357
1591664212fa6c14eebcee5b33d31fe2df)
```

Generator 1 (`G1`) is the base point of Ed448. Generator 2 (`G2`) was created
following this post [\[13\]](#references) and with this code
[\[9\]](#references) that works as follows:

1. Select `x`, a "nothing up my sleeve" value (a value chosen above suspicion
   of hidden properties). In this case, we choose `decaf_448_g2`.
2. Hash the base point to prevent a theoretical backdoor mentioned by Stanislav
   Smyshlaev: `hashed_base = SHAKE-256(base_point)`
3. Hash the `x` into an array of 512 bits. These will be used as the uniform
   random seed: `seed = SHAKE-256(x)`
4. Hash the base point with the uniform random seed:
   `encoded_point = SHAKE-256(hashed_base, seed)`
5. Apply elligator 2 [\[14\]](#references). Use
   `point_from_hash_uniform` from Mike Hamburg's ed448 code
   [\[15\]](#references) which maps a hash buffer to the curve:
   `p = point_from_hash_uniform(encoded_point)`

#### Dual Receiver Key Generation: DRGen()

1. Pick random values `x1, x2, y1, y2, z` in Z_q.
2. Compute group elements
  - `C = G1 * x1 + G2 * x2`
  - `D = G1 * y1 + G2 * y2`
  - `H = G1 * z`.
3. The public key is `PK = {C, D, H}` and the secret key is
   `sk = {x1, x2, y1, y2, z}`.

#### Dual Receiver Encryption: DREnc(PK1, PK2, K)

Let `{C1, D1, H1} = PK1` and `{C2, D2, H2} = PK2`
`C1`, `D1`, `H1`, `C2`, `D2`, and `H2` should be checked to verify
they are on curve 448.

1. Pick random values `k1, k2` in Z_q.
2. For i ∈ {1, 2}:
  1. Compute
    - `U1i = G1 * ki`
    - `U2i = G2 * ki`
    - `Ei = (Hi * ki) + K`
  2. Compute `αi = HashToScalar(U1i || U2i || Ei)`.
  3. Compute `Vi = Ci * ki + Di * (ki * αi)`
3. Generate a NIZKPK:
  1. for i ∈ {1, 2}:
    1. Pick random value `ti` in Z_q.
    2. Compute
      - `T1i = G1 * ti`
      - `T2i = G2 * ti`
      - `T3i = (Ci + Di * αi) * ti`
  2. Compute `T4 = H1 * t1 - H2 * t2`.
  3. Compute
    - `gV = G1 || G2 || q`
    - `pV = C1 || D1 || H1 || C2 || D2 || H2`
    - `eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2`
    - `zV = T11 || T21 || T31 || T12 || T22 || T32 || T4`
    - `l = HashToScalar(gV || pV || eV || zV)`
  4. Generate for i ∈ {1,2}:
    1. Compute `ni = ti - l * ki (mod q)`.
4. Send `gamma = (U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2)`.

#### Dual Receiver Decryption: DRDec(PK1, PK2, ski, gamma):

Let `{C1, D1, H1} = PK1`, `{C2, D2, H2} = PK2` and `{x1i, x2i, y1i, y2i, zi} =
ski`.
ski is the secret key of the person decrypting the message.
`C1`, `D1`, `H1`, `C2`, `D2`, and `H2` should be checked to verify
they are on curve 448.

1. Parse `gamma` to retrieve components
  `(U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, phi) = gamma`.
2. Verify NIZKPK:
  1. for j ∈ {1, 2} compute:
    1. `αj = HashToScalar(U1j || U2j || Ej)`
    2. `T1j = G1 * nj + U1j * l`
    3. `T2j = G2 * nj + U2j * l`
    4. `T3j = (Cj + Dj * αj) * nj + Vj * l`
  2. Compute `T4 = H1 * n1 - H2 * n2 + (E1-E2) * l`
  3. Compute
    - `gV = G1 || G2 || q`
    - `pV = C1 || D1 || H1 || C2 || D2 || H2`
    - `eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2`
    - `zV = T11 || T21 || T31 || T12 || T22 || T32 || T4`
    - `l' = HashToScalar(gV || pV || eV || zV)`
  4. Verify `l' ≟ l`.
  5. Verify `U1i * x1i + U2i * x2i + (U1i * y1i + U2i * y2i) * αi ≟ Vi`.
3. Recover `K = Ei - U1i * zi`.

### ROM Authentication

The Authentication scheme consists of two functions:

`sigma = Auth(A_1, a_1, {A_1, A_2, A_3}, m)`, an authentication function.

`Verify({A_1, A_2, A_3}, sigma, m)`, a verification function.

#### Domain parameters

We reuse the previously defined G1 generator in Cramer-Shoup of DRE:

```
G1 = (11781216126343694673728248434331006466518053535701637341687908214793940427
7809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf393
2d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)
```

#### Authentication: Auth(A1, a1, {A1, A2, A3}, m):

A1 is the public value associated with a1, that is, `A1 = G1*a1`.
m is the message to authenticate.

`A1`, `A2`, and `A3` should be checked to verify they are on curve 448.

1. Pick random values `t1, c2, c3, r2, r3` in Z_q.
2. Compute `T1 = G1 * t1`.
3. Compute `T2 = G1 * r2 + A2 * c2`.
4. Compute `T3 = G1 * r3 + A3 * c3`.
5. Compute `c = HashToScalar(G1 || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Compute `c1 = c - c2 - c3 (mod q)`.
7. Compute `r1 = t1 - c1 * a1 (mod q)`.
8. Send `sigma = (c1, r1, c2, r2, c3, r3)`.

#### Verification: Verify({A1, A2, A3}, sigma, m)

`A1`, `A2`, and `A3` should be checked to verify they are on curve 448.

1. Parse sigma to retrieve components `(c1, r1, c2, r2, c3, r3)`.
2. Compute `T1 = G1 * r1 + A1 * c1`
3. Compute `T2 = G1 * r2 + A2 * c2`
4. Compute `T3 = G1 * r3 + A3 * c3`
5. Compute `c = HashToScalar(G1 || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Check if `c ≟ c1 + c2 + c3 (mod q)`.

### HashToScalar(d)

d is an array of bytes.

1. Compute `h = SHA3-512(d)` as an unsigned value, big-endian.
2. Return `h (mod q)`

### Modify an encrypted data message

In this example, a forger guesses that "hi" is at the beginning of an encrypted message.
Thus, its offset is 0. The forger wants to replace "hi" with "yo".

  ```
  offset = 0
  old_text = "hi"
  new_text = "yo"
  textlength = string_length_of("hi")
  encrypted_message_length = get_from_data_message()
  old_encrypted_message = get_from_data_message()

  for (i=0; i < textlength && offset+i < encrypted_message_length; i++) {
      old_encrypted_message[offset+i] ^= old_text[i] ^ new_text[i]
  }

  new_encrypted_message = old_encrypted_message

  new_mac_tag = mac(new_encrypted_message, revealed_mac_key)

  new_data_message = replace(old_data_message, new_encrypted_message, new_mac_tag)

  ```

### References

1. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf "N. Unger, I. Goldberg: Improved Techniques for Implementing Strongly Deniable Authenticated Key Exchanges"
2. https://whispersystems.org/docs/specifications/doubleratchet "Trevor Perrin (editor), Moxie Marlinspike: The Double Ratchet Algorithm"
3. https://mikehamburg.com/papers/goldilocks/goldilocks.pdf "M. Hamburg: Ed448-Goldilocks, a new elliptic curve"
4. http://www.ietf.org/rfc/rfc7748.txt "A. Langley, M. Hamburg, and S. Turner: Elliptic Curves for Security.” Internet Engineering Task Force; RFC 7748 (Informational); IETF, Jan-2016"
5. https://www.ietf.org/rfc/rfc3526.txt "M. Kojo: More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)"
6. https://eprint.iacr.org/2015/673.pdf "Mike Hamburg: Decaf: Eliminating cofactors through point compression"
7. https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html "Off-the-Record Messaging Protocol version 3"
8. https://xmpp.org/extensions/xep-0060.pdf "P. Millard, P. Saint-Andre and R. Meijer: XEP-0060: Publish-Subscribe"
9. https://github.com/twstrike/cramershoup/blob/master/src/test.c#L60
10. https://ed25519.cr.yp.to/python/ed25519.py "Daniel Bernstein: ed25519"
11. https://ed25519.cr.yp.to/ed25519-20110926.pdf "Daniel Bernstein, Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang: High-speed high-security signatures"
12. https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05 "S. Josefsson and I. Liusvaara: Edwards-curve Digital Signature Algorithm (EdDSA)"
13. https://moderncrypto.org/mail-archive/curves/2017/000840.html
14. https://elligator.cr.yp.to/elligator-20130828.pdf "Daniel J. Bernstein, Mike Hamburg, Anna Krasnova and Tanja Lange: Elligator: Elliptic-curve points
indistinguishable from uniform random strings"
15. https://sourceforge.net/p/ed448goldilocks/code/ci/decaf/tree/src/decaf_fast.c#l1125