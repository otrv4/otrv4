# OTR version 4

OTRv4 is a new version of OTR that provides a deniable authenticated key
exchange and better forward secrecy through the use of double ratcheting. OTR
works on top of an existing messaging protocol, like XMPP.

???: The spec currently refers to DAKE meaning interactive DAKE. We need to
replace it and identify when DAKE is used in the broader sense.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)
1. [High Level Overview](#high-level-overview)
1. [Assumptions](#assumptions)
1. [Security Properties](#security-properties)
1. [Notation and parameters](#notation-and-parameters)
    1. [Notation](#notation)
    1. [Elliptic Curve Parameters](#elliptic-curve-parameters)
    1. [3072-bit Diffie-Hellman Parameters](#3072-bit-diffie-hellman-parameters)
1. [Data Types](#data-types)
    1. [Encoding Ed448 Points](#encoding-ed448-points)
    1. [Decoding Ed448 Points](#decoding-ed448-points)
    1. [Serializing the SNIZKPK Authentication](#serializing-the-snizkpk-authentication)
    1. [Public keys and fingerprints](#public-keys-and-fingerprints)
    1. [TLV Types](#tlv-types)
    1. [OTR Error Messages](#otr-error-messages)
1. [Key management](#key-management)
    1. [Generating ECDH and DH keys](#generating-ecdh-and-dh-keys)
    1. [Shared secrets](#shared-secrets)
    1. [Deciding between chain keys](#deciding-between-chain-keys)
    1. [Deriving Double Ratchet keys](#deriving-double-ratchet-keys)
    1. [Rotating ECDH keys and mix key](#rotating-ecdh-keys-and-mix-key)
    1. [Deriving new chain keys](#deriving-new-chain-keys)
    1. [Computing chain keys](#computing-chain-keys)
    1. [Calculating encryption and MAC keys](#calculating-encryption-and-mac-keys)
    1. [Resetting state variables and key variables](#resetting-state-variables-and-key-variables)
1. [Online Conversation Initialization](#online-conversation-initialization)
    1. [Requesting conversation with older OTR versions](#requesting-conversation-with-older-otr-versions)
    1. [User Profile](#user-profile)
    1. [Interactive Deniable Authenticated Key Exchange (DAKE)](#interactive-deniable-authenticated-key-exchange-dake)
1. [Offline Conversation Initialization](#offline-conversation-initialization)
1. [Data Exchange](#data-exchange)
    1. [Data Message](#data-message)
    1. [Revealing MAC Keys](#revealing-mac-keys)
1. [Fragmentation](#fragmentation)
    1. [Transmitting Fragments](#transmitting-fragments)
    1. [Receiving Fragments](#receiving-fragments)
1. [The protocol state machine](#the-protocol-state-machine)
    1. [Protocol states](#protocol-states)
    1. [Protocol events](#protocol-events)
1. [Socialist Millionaires Protocol (SMP)](#socialist-millionaires-protocol-smp)
    1. [SMP Overview](#smp-overview)
    1. [Secret information](#secret-information)
    1. [SMP Hash function](#smp-hash-function)
    1. [SMP message 1](#smp-message-1)
    1. [SMP message 2](#smp-message-2)
    1. [SMP message 3](#smp-message-3)
    1. [SMP message 4](#smp-message-4)
    1. [The SMP state machine](#the-smp-state-machine)
1. [Implementation Notes](#implementation-notes)
    1. [Considerations for networks that allow multiple devices](#considerations-for-networks-that-allow-multiple-devices)
1. [Forging Transcripts](#forging-transcripts)
1. [Appendices](#appendices)
    1. [SNIZKPK Authentication](#snizkpk-authentication)
    1. [HashToScalar](#hashtoscalar)
    1. [Modify an encrypted data message](#modify-an-encrypted-data-message)
    1. [OTRv3 Specific Encoded Messages](#otrv3-specific-encoded-messages)
    1. [OTRv3 Protocol State Machine](#otrv3-protocol-state-machine)
    1. [References](#references)

## Main Changes over Version 3

- Security level raised to 224 bits and based on elliptic curve cryptography
  (ECC).
- Additional protection against transcript decryption in the case of ECC
  compromise.
- The cryptographic primitives and protocols have been updated:
  - Deniable authenticated key exchange using DAKEZ [\[1\]](#references).
  - Key management using the Double Ratchet Algorithm [\[2\]](#references).
  - Upgraded SHA-1 and SHA-2 to SHA-3.
  - Switched from AES to XSalsa20.
- Explicit instructions for producing forged transcripts using the same
  functions used to conduct honest conversations.

## High Level Overview

TODO: Add the non-interactive overview.

```
Alice                                            Bob
--------------------------------------------------------------------------------
Requests OTR conversation           ------------->

Establishes Conversation with       <------------>  Establishes Conversation with
Deniable Authenticated Key Exchange                 Deniable Authenticated Key Exchange

Exchanges Data Messages             <------------>  Exchanges Data Messages
```

An OTRv4 conversation can begin after one participant requests a conversation.
This includes an advertisement of which versions they support. If the other
participant supports OTRv4 as the highest compatible version, a deniable, authenticated
key exchange (DAKE) is used to establish a secure channel. Encrypted messages are
then exchanged in this secure channel with forward secrecy.

## Assumptions

Both participants are online at the start of a conversation.

Messages in a conversation can be exchanged over an insecure channel, where an
attacker can eavesdrop or interfere with the encrypted messages.

The network model provides in-order delivery of messages, and some messages
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

In the DAKE, although access to one participant's private long term key is
required for authentication, both participants can deny having used their
private long term keys in this process. An external cryptographic expert will
be able to prove that one person between the two used their long term private
key for the authentication, but they will not be able to identify whose key was
used. This provides deniability for those participating in the DAKE, whereas
the AKE of OTRv3 is not deniable.

Once an OTRv4 channel has been created with the DAKE, all data messages
transmitted through this channel are confidential and their integrity to the
participants is protected. In addition, the MAC keys used to validate
each message are revealed afterwards. This allows for forgeability of the data
messages and consequent deniability of their contents.

If key material used to encrypt a particular data message is compromised, previous
messages are protected. In addition, future messages are protected by the Diffie-
Hellman and Elliptic Curve Diffie-Hellman ratchets.

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

OTRv4 uses the Ed448-Goldilocks [\[3\]](#references) elliptic curve
[\[4\]](#references), which defines the following parameters:

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
using the rules for multi-precision integers (MPIs). MPIs are defined on
[Data Types](#data-types) section.

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

Subprime (dh_q):
  (dh_p - 1) / 2

Hexadecimal value of dh_q:
  7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68
  94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E
  F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122
  F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6
  F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F6722D9E
  E1003E5C 50B1DF82 CC6D241B 0E2AE9CD 348B1FD4 7E9267AF
  C1B2AE91 EE51D6CB 0E3179AB 1042A95D CF6A9483 B84B4B36
  B3861AA7 255E4C02 78BA3604 650C10BE 19482F23 171B671D
  F1CF3B96 0C074301 CD93C1D1 7603D147 DAE2AEF8 37A62964
  EF15E5FB 4AAC0B8C 1CCAA4BE 754AB572 8AE9130C 4C7D0288
  0AB9472D 45556216 D6998B86 82283D19 D42A90D5 EF8E5D32
  767DC282 2C6DF785 457538AB AE83063E D9CB87C2 D370F263
  D5FAD746 6D8499EB 8F464A70 2512B0CE E771E913 0D697735
  F897FD03 6CC50432 6C3B0139 9F643532 290F958C 0BBD9006
  5DF08BAB BD30AEB6 3B84C460 5D6CA371 047127D0 3A72D598
  A1EDADFE 707E8847 25C16890 549D6965 7FFFFFFF FFFFFFFF

```

Note that this means that whenever you see an operation on a field element
from the above group, the operation should be done modulo the prime `dh_p`.

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

Ed448 point (POINT):
  56 bytes data

User Profile (USER-PROF):
  Detailed in "User Profile Data Type" section
```

In order to serialize and deserialize the point, use Encode and Decode as
defined on Appendix A.1 (Encoding) and A.2 (Decoding) in Mike Hamburg's Decaf
paper [\[6\]](#references). These functions work as follows:


### Encoding Ed448 Points

Using the Jacobi quartic, a point `P` can by encoded by the s-coordinate of the
coset representative `(s, t)`, where `s` is non-negative and finite, and `t / s`
is non-negative or infinite.

We wish to compute `s` as `(1 ± sqrt(1 - (a * x)^2)) / a * x` and
`t / s` as `∓ 2 * sqrt(1 - (a * x) ^ 2) / x * y`.

Note that from the curve equation, it is known that:
`(1 - ax^2) * (1 - y^2) = 1 + (a * x)^2 * y^2 - (y^2 + (a * x)^2) = (a - d) * x^2 * y^2`,
so that `sqrt(1 - (a * x^2)) / x * y = ± sqrt((a - d) / (1 - y^2))`.

In extended homogenous coordinates:
`1/x^2 = (a - (d * y)^2) / 1 - y^2) = ((a * Z)^2 - (d * Y)^2) / (Z^2 - Y^2)`,
so that `1/x = ((a * Z * X) - (d * Y * T))/ (Z^2 - Y^2)`

1. Compute `r = 1/ sqrt((a - d) * (Z + Y) * (Z - Y))`
2. Compute `u = (a - d) * r`
3. Compute `r = -r` if `-2 * u * Z` is negative
4. Compute `s = | u * (r * ((a * Z * X) - (d * Y * T)) + Y) / a|`

### Decoding Ed448 Points

Given s, compute:
`(x, y) = (2 * s / (1 + (a * s)^2),
(1 - (a * s)^ 2 / sqrt(a^2 * s^4 + (2 * a - 4 * d) * s^2 + 1))`

1. Compute `X = 2 * s`
2. Compute `Z = 1 + a * s^2`
3. Compute `u = Z^2 - (4 * d) * s^2`
4. Check that `v` equals:
   1. `1 / sqrt(u * s^2)` if `u * s^2` is square and non-zero
   2. `0` if `u * s^2 = 0`
   3. reject if `u * s^2` is not square
5. Compute `v` = `-v` if `u * v` is negative
6. Compute `w = v * s * (2 - Z)`
7. Compute `w = w + 1` if `s = 0`
8. Compute `Y = w * Z`
9. Compute `T = w * X`
10. Construct the point `P` as `P = (X : Y : Z : T)`

### Serializing the SNIZKPK Authentication

A signature non-interactive zero-knowledge proof of knowledge (SNIZKPK) is
serialized as follows:

```
SNIZKPK Authentication (SNIZKPK):
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
OTR4 public authentication ElGamal key (EL-GAMAL-PUBKEY):

  Pubkey type (SHORT)
    ElGamal public keys have type 0x0010

    H (POINT)
      H is the ElGamal public key generated (H = G1 * r).
```

OTRv4 public keys have fingerprints, which are hex strings that serve as
identifiers for the public key. The fingerprint is calculated by taking the
SHA3-512 hash of the byte-level representation of the public key.

### TLV Types

Each TLV record is of the form:

Type (SHORT)
  The type of this record. Records with unrecognized types should be ignored.
Length (SHORT)
  The length of the following field
Value (len BYTEs) [where len is the value of the Length field]
  Any pertinent data for the record type.

OTRv4 supports the majority of the TLV record types from OTRv3. The ones not
supported state so. They are:

```
Type 0: Padding
  The value may be an arbitrary amount of data. This data should be ignored.
  This type can be used to disguise the length of a plaintext message.

Type 1: Disconnected
  Closes the connection.

Type 2: SMP Message 1
  The value represents the initial message of the Socialist Millionaires'
  Protocol (SMP), described below.

Type 3: SMP Message 2
  The value represents the second message in an instance of the SMP.

Type 4: SMP Message 3
  The value represents the third message in an instance of the SMP.

Type 5: SMP Message 4
  The value represents the final message in an instance of the SMP.

Type 6: SMP Abort Message
  If the user cancels the SMP prematurely or encounters an error in the
  protocol and cannot continue, you may send a message (possibly with an empty
  human-readable part) with this TLV type to instruct the other party's client
  to abort the protocol. The associated length should be zero and the
  associated value should be empty. If you receive a TLV of this type,
  you should change the SMP state to 'SMP_EXPECT1' (see below).

Type 7: SMP Message 1Q
  Only used by OTRv3, and not in OTRv4.
  Like a SMP Message 1, but its value begins with a NUL-terminated
  user-specified question.

Type 8: Extra symmetric key
  Only used by OTRv3, and not in OTRv4.
  If you wish to use the extra symmetric key, compute it as outlined in the
  section "Extra symmetric key" [\[2\]](#references). Then, send this 'type 8 TLV' to your
  peer to indicate that you'd like to use it. The value of the TLV begins with
  a 4-byte indication of what this symmetric key will be used for
  (file transfer, voice encryption, etc). After that, the contents are
  use-specific (which file, etc): there are no predefined uses.
  Note that the value of the key itself is not placed into the TLV; your peer
  will compute it on its own.
```

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

In the DAKE, OTRv4 makes use of long-term ElGamal keys, ephemeral Elliptic
Curve Diffie-Hellman (ECDH) keys, and ephemeral Diffie-Hellman (DH) keys.

For exchanging data messages, OTRv4 makes use of both the DH ratchet (with ECDH)
and the symmetric-key ratchet from the Double Ratchet algorithm. If you wish to
understand the Double Ratchet in more detail then please refer to the spec
[\[2\]](#references) but to implement OTRv4 this is not necessary. OTRv4
contains everything necessary to implement the Double Ratchet in this context. A
cryptographic ratchet is a one-way mechanism for deriving new cryptographic keys
from previous keys. New keys cannot be used to calculate the old keys.

OTRv4 adds 3072-bit (384-byte) DH keys, called the mix key pair, to the
Double Ratchet algorithm. These keys are used to protect transcripts of data
messages in case ECC is broken. During the DAKE, both parties agree upon the
first set of DH keys. Then, during every third DH ratchet in the Double
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

The previously mentioned state variables are incremented and the key variable
values are replaced by these events:

* When you start a new [DAKE](#dake-overview) by sending or receiving an
  [Identity message](#identity-message).
* Upon completing the [DAKE](#dake-overview) by sending or receiving a
  [DRE-Auth Message](#dre-auth-message).
* [When you send and receive a Data Message](#data-exchange)
* [When you receive a TLV type 1 (Disconnect)](#receiving-a-tlv-type-1-disconnect-message)
* ???: What about when you start a non-interactive AKE?

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
  and `Ca` as the receiving chain key (`chain_r`).

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

The state variables are set to `0` and the key variables are set to `NIL` for
this channel.

## Online Conversation Initialization

OTRv4 will initialize through a [Query Message or a Whitespace
Tag](#user-requests-to-start-an-otr-conversation). After this, the conversation
is authenticated using the interactive DAKE.

### Requesting conversation with older OTR versions

Bob might respond to Alice's request or notification of willingness to start a
conversation using OTRv3. If this is the case and Alice supports version 3,
the protocol falls back to OTRv3 [\[7\]](#references). If Alice does not support
version 3, then this message is ignored.

### User Profile

OTRv4 introduces a user profile. The user profile contains the ElGamal
long term public key, signed information about supported versions, a signed
profile expiration date, and a singed optional transition signature.

Each participant maintains a user profile for authentication in the DAKE and for
publication. Publishing the user profile allows users to repudiate their
participation in OTRv4 conversations. When a user profile is published, it is
available from a public location, such as a server. Each implementation may
decide how to publish the profile. For example, one client may publish profiles
to a server pool (similar to a keyserver pool, where PGP public keys can be
published). Another client may use XMPP's publish-subscribe extension
(XEP-0060 [\[8\]](#references)) for publishing profiles.

When the user profile expires, it should be updated. Client implementation
should determine the frequency of user's profile expiration and renewal. The
recommended expiration time is two weeks.

Both parties include the user profile in the DAKE. Participants in the DAKE do
not request the profile from the site of publication. Both the published profile
and the profile used in the DAKE should match each other.

#### Creating a User Profile

To create a user profile, assemble:

1. User's ElGamal long term public key.
2. Versions: a string corresponding to the user's supported OTR versions.
   A user profile can advertise multiple OTR versions. The format is described
   under the section [Establishing Versions](#establishing-versions) below.
3. Profile Expiration: Expiration date in standard Unix 64-bit format
   (seconds since the midnight starting Jan 1, 1970, UTC, ignoring leap
   seconds).
4. ????: Profile Signature: One of the ElGamal secret key values (`z`) and its
   generator (`G1`) is used to create signatures of the entire profile
   excluding the signature itself. The size of the signature is 112 bytes. It is
   created using the [Ed448 signature algorithm](#user-profile-signature).
5. Transition Signature (optional): A signature of the profile excluding Profile
   Signatures and the user's OTRv3 DSA key. The Transition Signature enables
   contacts that trust user's version 3 DSA key to trust the user's profile in
   version 4. This is only used if the user supports versions 3 and 4.

After the profile is created, it must be published in a public place, like an
untrusted server.

#### Establishing Versions

A valid versions string can be created by concatenating supported version
numbers together in any order. For example, a user who supports versions 3 and 4
will have the version string "43" or "34" in their profile (2 bytes). A user who
only supports version 4 will have "4" (1 byte). Thus, a version string has
varying size, and it is represented as a DATA type with its length specified.

Invalid version strings contain "2" or "1". The OTRv4 specification supports up
to OTR version 3, and thus do not support versions 2 and 1, i.e. version strings
of "32" or "31". Any other string that is not "4", "3", "2" or "1" should be
ignored.

#### Validating a User Profile

* Verify that the user profile signature is valid.
* Verify that the user profile is not expired.
* Verify that the versions field contains "4".

#### Renewing a Profile

If a renewed profile is not published in a public place, the user's
participation deniability is at risk. Participation deniability is also at risk
if the only publicly available profile is expired. In addition, an expired
profile received in the DAKE is considered invalid.

Before the profile expires, the user must publish an updated profile with a
new expiration date. The client establishes the frequency of expiration - this
can be configurable. A recommended value is two weeks.

#### Creating a User Profile Signature

???: We need to review this: why is it specific to "decaf" signatures?

The user profile signature is based on a variant of Schnorr's signature
algorithm defined by Mike Hamburg. An overview of how the signature works
can be found on [\[3\]](#references) and the [implementation function:
decaf\_448\_sign\_shake](https://sourceforge.net/p/ed448goldilocks/code/ci/decaf/tree/src/decaf_crypto.c#l117)
provides more detail.

OTRv4 uses the following steps to create a signature:

   ```
   signature = sign(message, private_key)
   ```

1. Derive an intermediary nonce by using SHA3 SHAKE-256 of the message, of a random
   value `random_v`, and of a specific string "decaf\_448\_sign\_shake". Decode
   this value into a scalar and reduce it mod the order of the base point
   [q](#elliptic-curve-parameters).

   ```
   random_v = new_random_value()
   output = SHAKE-256(message || random_v || "decaf\_448\_sign\_shake")
   intermediary_nonce = decode(output) % q
   ```

2. Use this intermediary nonce to create a temporary signature by computing
   `nonce * G1` and encoding the output into an array of bytes.

   ```
   temporary_signature = encode(G1 * intermediary_nonce)
   ```

3. Use SHAKE-256 to hash the message, the public key, and the temporary
   signature. The `public_key` is the [`h` value](#dual-receiver-key-generation-drgen)
   of the ElGamal public key. Decode this value into a scalar and reduce
   it mod the order of the base point [q](#elliptic-curve-parameters).

   ```
   output = SHAKE256(message || public_key || temporary_signature)
   challenge = decode(output) % q
   ```

4. Scalar multiply the challenge with the secret key. The `secret_key` is the
   [`z`](#dual-receiver-key-generation-drgen) value of the ElGamal private
   key.
   Derive the final nonce by scalar subtracting the product of the
   multiplication from the intermediary nonce.

   ```
   nonce = intermediary_nonce - challenge * secret_key
   ```

5. Concatenate the final nonce and the temporary signature into the signature.
   The nonce and the temporary signature are each 56 bytes each, giving a total
   size of 112 bytes.

#### Verify a User Profile Signature

An overview of how to verify this signature can be found on the [implementation
function: decaf\_448\_verify\_shake](https://sourceforge.net/p/ed448goldilocks/code/ci/decaf/tree/src/decaf_crypto.c#l163).

   ```
   valid = verify(signature, message, public_key)
   ```
These are the steps to verify the signature:

1. Derive a challenge by using a SHAKE-256 of the message, a public key, and
   the temporary signature (the first 56 bytes of the signature). The public key
   is the [`h`](#dual-receiver-key-generation-drgen) value of the ElGamal
   long term public key in the profile. Decode this value into a scalar and
   reduce it mod the order of the base point [q](#elliptic-curve-parameters).

   ```
   output = SHAKE-256(message || public_key || temporary_signature)
   challenge = decode(output) % q
   ```

2. Decode the temporary signature and the public key into points. This will
   verify that the temporary signature and the public key are points on the
   curve Ed448.

   ```
   temporary_signature_point = decode(temporary_signature)
   public_key_point = decode(public_key)
   ```

3. Decode the nonce into a scalar. This will verify that the nonce is a scalar
   within order of the base point.

   ```
   nonce = decode(nonce_bytes)
   ```

4. Compute: the addition of the multiplication of `G1` (the base point) with the
   `nonce` and the multiplication of the `public_key_point` with the `challenge`.

   ```
   result_point  = G1 * nonce + public_key_point * challenge
   ```

5. Check that the `result_point` and the `temporary_signature_point` are equal.
   If they are equal, the signature is valid.

#### User Profile Data Type

```
User Profile (USER-PROF):
  ElGamal public key (EL-GAMAL-PUBKEY)
  Versions (DATA)
  Profile Expiration (PROF-EXP)
  Profile Signature (SCHNORR-SIG)
  (optional) Transitional Signature (SIG)

Profile Expiration (PROF-EXP):
  8 bytes signed value, big-endian
```

SIG refers to the `OTR version 3 DSA Signature` with the structure. Refer to
'DSA signature' on OTRv3 for more information:

```
DSA signature (SIG):
  (len is the length of the DSA public parameter q, which in current
  implementations is 20 bytes)
  len byte unsigned r, big-endian
  len byte unsigned s, big-endian
```

???: Is this still a Schnorr Signature?
SCHNORR-SIG refers to the `OTR version 4 signature`:

```
Schnorr signature (SCHNORR-SIG):
  (len is the expected length of the signature, which is 112 bytes)
  len byte unsigned value, big-endian
```

### Interactive Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the interactive DAKE. This is a way to
mutually agree upon shared keys for the two parties and authenticate one another
while providing participation deniability.

This protocol is derived from the DAKEZ protocol [\[1\]](#references), which
uses a signature non-interactive zero-knowledge proof of knowledge (SNIZKPK) for
authentication (Auth).

Alice's long-term ElGamal key-pair is `(ska, PKa)` and Bob's long-term ElGamal
key-pair is `(skb, PKb)`. Both key pairs are generated by `PK = G1 * sk`.

#### Interactive DAKE Overview

TODO: This is wrong. There one extra message.

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
    * Validates the received ECDH ephemeral public key is on curve Ed448 and
      sets it as `their_ecdh`.
    * Validates that the received DH ephemeral public key is on the correct
      group and sets it as `their_dh`.
2. Generates and sets `our_ecdh` as ephemeral ECDH keys.
3. Generates and sets `our_dh` as ephemeral 3072-bit DH keys.
4. Sends Bob a Auth-R message (see [Auth-R message](#auth-r-message) section).


**Bob:**

1. Receives Auth-R message from Alice:
    * Validates Alice's User Profile.
    * Picks the highest compatible version of OTR listed on Alice's profile, and
      follows the specification for this version. Version prioritization is
      explained [here](#version-priority) If the versions are incompatible, Bob
      does not send any further messages.
    * Verify the authentication `sigma` (see [Auth-R message](#auth-r-message) section).
    * Verify `(Y, B)` in the message is an Identity message that Bob previously sent
      and has not been used.
3. Retrieve ephemeral public keys from Alice:
    * Validates the received ECDH ephemeral public key is on curve Ed448 and
      sets it as `their_ecdh`.
    * Validates that the received DH ephemeral public key is on the correct
      group and sets it as `their_dh`.
4. Sends Bob a Auth-I message (see [Auth-I message](#auth-i-message) section).
5. At this point, the DAKE is complete for Bob:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 0 (which means she will ratchet again).
    * Calculates ECDH shared secret `K_ecdh`.
    * Calculates DH shared secret `k_dh` and `mix_key`.
    * Calculates Mixed shared secret `K = SHA3-512(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: it is the first 8 bytes of `SHA3-256(0x00 || K)`.
    * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = calculate_ratchet_keys(K)`.
    * [Decides which chain key he will use](#deciding-between-chain-keys).

**Alice:**

1. Receives an Auth-I message from Bob:
    * Verify the authentication `sigma` (see [Auth-I message](#auth-i-message) section).
2. At this point, the interactive DAKE is complete for Alice:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 1.
    * Calculates ECDH shared secret `K_ecdh`.
    * Calculates DH shared secret `k_dh` and `mix_key`.
    * Calculates Mixed shared secret `K = SHA3-512(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: the first 8 bytes of `SHA3-256(0x00 || K)`.
    * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = calculate_ratchet_keys(K)`.
    * [Decides which chain key she will use](#deciding-between-chain-keys).

#### Identity message

This is the first message of the DAKE. Bob sends it to Alice to commit to a
choice of DH and ECDH key. A valid Identity message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile).
2. Generate an ephemeral ECDH key pair:
  * secret key `y` (56 bytes).
  * public key `Y`.
3. Generate an ephemeral DH key pair:
  * secret key `b` (80 bytes).
  * public key `B`.

To verify an Identity message:

* Validate the User Profile.
* Verify that the point `Y` received is on curve Ed448.
* Verify that the DH public key `B` is from the correct group and that it
  does not degenerate.

An Identity message is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x08.
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

#### Auth-R message

This is the second message of the DAKE. Alice sends it to Bob to commit to a
choice of her ECDH ephemeral key and her DH ephemeral key, and acknowledgment
of Bob's ECDH ephemeral key and DH ephemeral key. This acknowledgement includes
a validation that Bob's ECDH key is on the curve Ed448 and his DH key is in the
correct group.

A valid Auth-R message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile).
2. Generate an ephemeral ECDH key pair:
  * secret key `x` (56 bytes).
  * public key `X`.
3. Generate an ephemeral DH key pair:
  * secret key `a` (80 bytes).
  * public key `A`.
4. Compute `t = 0x0 || Bobs_User_Profile || Alices_User_Profile || Y || X || B || A`.
5. Compute `sigma = Auth(Pka, ska, {Pkb, Pka, Y}, t)`.

To verify an Auth-R message:

1. Validate the user profile, and extract `Pka` from it.
2. Compute `t = 0x0 || Bobs_User_Profile || Alices_User_Profile || Y || X || B || A`.
3. Verify the `sigma` with [SNIZKPK Authentication](#snizkpk-authentication),
that is `sigma == Verify({Pkb, Pka, Y}, t)`.

An Auth-R is an OTR message encoded as:

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
X (POINT)
  The ephemeral public ECDH key.
A (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase,
  this is NOT a POINT.
sigma (SNIZKPK)
  The SNIZKPK Auth value.
```

#### Auth-I message

This is the final message of the DAKE. Bob sends it to Alice to [complete with a
description].

A valid Auth-I message is generated as follows:

1. Compute `t = 0x1 || Bobs_User_Profile || Alices_User_Profile || Y || X || B || A`.
2. Compute `sigma = Auth(Pkb, skb, {Pkb, Pka, X}, t)`.

To verify the Auth-I message:

1. Compute `t = 0x1 || Bobs_User_Profile || Alices_User_Profile || Y || X || B || A`.
2. Verify the `sigma` with [SNIZKPK Authentication](#snizkpk-authentication),
that is `sigma == Verify({Pkb, Pka, X}, t)`.

An Auth-I is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x80.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient.
sigma (SNIZKPK)
  The SNIZKPK Auth value.
```

## Offline Conversation Initialization

TODO: Improve this, but a rough description of how it works is:

1. You ask for a pre-key using a protocol to be defined in another spec.
2. You send the last ZDH message + an encrypted data message.
3. You keep ratcheting at the chain-key level to send additional messages.

We should highlight the problems of keep using the same session for a long time
and how OTR design uses a heartbeat to force key refresh, and how there's a
trade-off between the duration of the conversation and the limited number of
pre-keys.

TODO: Add a note about the server is untrusted and this is OK.

### Non-interactive Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the non-interactive DAKE. This is a way to
mutually agree upon shared keys for the two parties and authenticate one another
while providing participation deniability. Unlike the interactive DAKE, the
non-interactive DAKE does not provide online deniability for the receiver.

This protocol is derived from the ZDH protocol [\[1\]](#references), which
uses a signature non-interactive zero-knowledge proof of knowledge (SNIZKPK) for
authentication (Auth).

Alice's long-term ElGamal key-pair is `(ska, PKa)` and Bob's long-term ElGamal
key-pair is `(skb, PKb)`. Both key pairs are generated by `PK = G1 * sk`.

#### Non-interactive DAKE Overview

```
Alice                         Server                               Bob
----------------------------------------------------------------------
Publish pre-key ------------->
                                     <------------- Request pre-key
                                     Pre-keys -------------------->
      <---------------------------------------- Unamed LAST MESSAGE
                                                + Encrypted data message
Verify & Decrypt message
```

TODO: Add the same outline for the message exchange.

**Bob:**

DO THIS

**Server**

DO THAT

**Alice:**

DO THAT

**Bob:**

...

### Publishing pre-keys

A OTRv4 client must generate pre-keys and publish them to a pre-key server using
a pre-key publishing protocol, described in another specification.

In order to maintain deniability the pre-key publishing protocol must use a DAKE
to authenticate the publisher.

### Obtaining pre-keys

The server may return more than 1 pre-key and we need to say this is valid and how to act.
TODO: Who should decide on how to act? The client or the protocol?

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange [data messages](#data-message) initialized with the shared
secret established in the DAKE. Detailed validation and processing of each data
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
  See 'Revealing MAC Keys section'.
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

### Receiving Fragments

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

WAITING_AUTH_R

  This is the Auth message sent by the Responder.

WAITING_AUTH_I

  This is the Auth message sent by the Initiator.

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

If Alice wishes to communicate to Bob that she would like to use OTR, she
sends a message containing the string "?OTRv" followed by an indication of
what versions of OTR she is willing to use with Bob. The versions she is
willing to use, whether she can set this on a global level or on a user by
user basis, this is up to the implementer. However, the requirement of
enabling users to choose whether they want to allow or disallow versions is
required. The version string is constructed as follows:

If she is willing to use OTR version 3, she appends a byte identifier for the
versions in question, followed by "?". The byte identifier for OTR version 3
is "3", and similarly for 4. Thus, if she is willing to use OTR versions 3 and
4, the following identifier would be "34". The order of the identifiers
between the "v" and the "?" does not matter, but none should be listed more
than once. The OTRv4 specification only supports versions 3 and higher. Thus,
query messages for older versions have been omitted.

Example query messages:

```
"?OTRv3?"
    Version 3
"?OTRv45x?"
    Version 4, and hypothetical future versions identified by "5" and "x"
"?OTRv?"
    A bizarre claim that Alice would like to start an OTR conversation, but is
    unwilling to speak any version of the protocol. Although this is
    syntactically valid, the receiver will not reply.
```

These strings may be hidden from the user (for example, in an attribute of an
HTML tag), and may be accompanied by an explanatory message ("Alice has
requested an Off-the-Record private conversation."). If Bob is willing to use
OTR with Alice (with a protocol version that Alice has offered), he should start
the AKE according to the highest compatible version he supports.

##### Whitespace Tags

If Alice wishes to communicate to Bob that she is willing to use OTR, she can
attach a special whitespace tag to any plaintext message she sends him. This tag
may occur anywhere in the message, and may be hidden from the user (as in the
[Query Messages](#query-messages), above).

The tag consists of the following 16 bytes, followed by one or more sets of 8
bytes indicating the version of OTR Alice is willing to use:

```
  Always send "\x20\x09\x20\x20\x09\x09\x09\x09" "\x20\x09\x20\x09\x20\x09\x20\x20",
  followed by one or more of:
    "\x20\x20\x09\x09\x20\x20\x09\x09" to indicate a willingness to use OTR version 3 with Bob
    "\x20\x20\x09\x09\x20\x09\x20\x20" to indicate a willingness to use OTR version 4 with Bob
```

If Bob is willing to use OTR with Alice (with the protocol version that Alice
has offered), he should start the AKE. On the other hand, if Alice receives a
plaintext message from Bob (rather than an initiation of the AKE), she should
stop sending him a whitespace tag.

#### Receiving plaintext without the whitespace tag

Display the message to the user.

If the state is `ENCRYPTED_MESSAGES`, `DAKE_IN_PROGRESS`, or `FINISHED`:

  * The user should be warned that the message received was unencrypted.

#### Receiving plaintext with the whitespace tag

Remove the whitespace tag and display the message to the user.

If the tag offers OTR version 4 and version 4 is allowed:

  * Send an Identity message.
  * Transition the state to `DAKE_IN_PROGRESS`.

Otherwise if the tag offers OTR version 3 and version 3 is allowed:

  * Send a version `3 D-H Commit Message`.
  * Transition authstate to `AUTHSTATE_AWAITING_DHKEY`.

#### Receiving a Query Message

If the Query Message offers OTR version 4 and version 4 is allowed:

  * Send an Identity message.
  * Transition the state to `DAKE_IN_PROGRESS`.

If the Query message offers OTR version 3 and version 3 is allowed:

  * Send a version `3 D-H Commit Message`.
  * Transition authstate to `AUTHSTATE_AWAITING_DHKEY`.

#### Receiving an Identity message

If the state is `START`:

  * Validate the Identity message and ignore the message if it fails.
  * Reply with an Auth-R message (TODO: link to section).
  * Transition to the `WAITING_AUTH_R` state.

If the state is `WAITING_AUTH_R`:

This indicates that both you and the other participant have sent Identity
messages to each other. This can happen if they send you an Identity message
before receiving yours.

To agree on an Identity message to use for this conversation:

  * Validate the Identity message and ignore the message if it fails.
  * Compare the `X` (as a 56-byte unsigned big-endian value) you sent in your
    Identity message with the value from the message you received.
  * If yours is the lower hash value:
    * Ignore the received Identity message, but resend your Identity message.
  * Otherwise:
    * Forget your old `X` value that you sent earlier.
    * Send an Auth-R message.
    * Transition state to `WAITING_AUTH_R`.

If the state is `WAITING_AUTH_I`:

  * Forget the old `their_ecdh` and `their_dh` from the previously received
    Identity message.
  * Send a new Auth-R message with the new values received.

There are a number of reasons this might happen, including:

  * Your correspondent simply started a new AKE.
  * Your correspondent resent his Identity Message, as specified above.

If the state is `ENCRYPTED_MESSAGES`:

  * Ignore the message.

#### Sending an Auth-R message

  * Generate an Auth-R Message.
  * Transition the state to `WAITING_AUTH_I`.

#### Receiving an Auth-R message

If the state is `WAITING_AUTH_R`:

  * Validate the Auth-R message and ignore the message if it fails.
  * Reply with an Auth-I message.
  * Transition state to `WAITING_AUTH_I`.

If the state is not `WAITING_AUTH_R`:

  * Ignore this message.

#### Sending an Auth-I message

  * Send an Auth-I Message.
  * Transition the state to `ENCRYPTED_MESSAGES`.
  * Initialize the double ratcheting.

#### Receiving an Auth-I message

If the state is `WAITING_AUTH_I`:

  * Validate the Auth-R message and ignore the message if it fails.
  * Transition state to `ENCRYPTED_MESSAGES`.
  * Initialize the double ratcheting.

If the state is not `WAITING_AUTH_I`:

  * Ignore this message.

#### Sending an encrypted data message

The `ENCRYPTED_MESSAGES` state is the only state where a participant is allowed
to send encrypted data messages.

If the state is `START` or `DAKE_IN_PROGRESS`, queue the message for encrypting
and sending when the participant transitions to the `ENCRYPTED_MESSAGES` state.

If the state is `FINISHED`, the participant must start another OTR conversation
to send encrypted messages.

#### Receiving an encrypted data message

If the version is 4:

  If the state is not `ENCRYPTED_MESSAGES`:

    * Inform the user that an unreadable encrypted message was received.
    * Reply with an Error Message with ERROR_1.

  Otherwise:

    * To validate the data message:
      * Verify the MAC tag.
      * Check if the message version is allowed.
      * Verify that the instance tags are consistent with those used in the DAKE.
      * Verify that the public ECDH key is on curve Ed448.
      * Verify that the public DH key is from the correct group.

    * If the message is not valid in any of the above steps, discard it and
      optionally pass along a warning to the user.

    * Use the ratchet id and the message id to compute the corresponding
      decryption key. Try to decrypt the message.

      * If the message cannot be decrypted and the `IGNORE_UNREADABLE` flag is not
      set:
        * Inform the user that an unreadable encrypted message was received.
        * Reply with an Error Message with ERROR_1.

      * If the message cannot be decrypted and the `IGNORE_UNREADABLE` flag is
      set:
        * Ignore it instead of producing an error or a notification to the user.

      * If the message can be decrypted:
        * Display the human-readable part (if it contains any) to the user. SMP
        TLVs should be addressed according to the SMP state machine.
        * Rotate root, chain and mix keys as appropriate.
        * If the received message contains a TLV type 1 (Disconnected) [TLV Types](#TLV-Types)
          forget all encryption keys for this correspondent and transition the
          state to `FINISHED`.

     * If you have not sent a message to this correspondent in some
       (configurable) time, send a "heartbeat" message.

If the version is 3:

Note that the states, messages and keys referred here are specific of OTRv3
Protocol.

  If msgstate is `MSGSTATE_ENCRYPTED`:

    * Verify the information (MAC, keyids, ctr value, etc.) in the message.
    * If the verification succeeds:
      * Decrypt the message and display the human-readable part (if non-empty)
        to the user.
      * Update the D-H encryption keys, if necessary.
      * If you have not sent a message to this correspondent in some
        (configurable) time, send a "heartbeat" message, consisting of a Data
	Message encoding an empty plaintext. The heartbeat message should have
	the `IGNORE_UNREADABLE` flag set.
      * If the received message contains a TLV type 1, forget all encryption
         keys for this correspondent, and transition msgstate to `MSGSTATE_FINISHED`.
    * Otherwise, inform the user that an unreadable encrypted message was
      received, and reply with an Error Message.

  If msgstate is `MSGSTATE_PLAINTEXT` or `MSGSTATE_FINISHED`:

    * Inform the user that an unreadable encrypted message was received, and
      reply with an Error Message.

#### Receiving an Error Message

* Detect if an error code exists in the form "ERROR__x" where x is a number.
* If the error code exists in the spec, display the human-readable error message
  to the user.
* Display the message in the user configured language.

If using version 3 and it is expected that the AKE will start when receiving a message:

  * Reply with a query message

#### User requests to end an OTR conversation

Send a data message, encoding a message with an empty human-readable part, and
TLV type 1. Transition to the `START` state.

#### Receiving a TLV type 1 (Disconnect) Message

If the version is 4:
  If a TLV type 1 is received in the `START` state, stay in that state, else
  transition to the START state and [reset the state variables and key
  variables](#resetting-state-variables-and-key-variables). Resetting state
  variables and key variables

If the version is 3:
  * Transition to 'MSGSTATE_FINISHED'.
  * Inform the user that its correspondent has closed its end of the private connection.

## Socialist Millionaires Protocol (SMP)

SMP in version 4 shares the same TLVs and flow as SMP in OTRv3 with the
following exceptions. For how OTRv3 handles SMP, please refer to the spec [\[2\]](#references).

In OTRv3, SMP Message 1 is used when a user does not specify an SMP question
and, if not, a SMP Message 1Q is used. OTRv4 is simplified to use only SMP
Message 1 for both cases. When a question is not present, the user specified
question section has length `0` and value `NULL`.

OTRv4 creates fingerprints using SHA3-512, which increases their size. Thus,
the size of the fingerprint in the "Secret Information" section of OTRv3
[\[7\]](#references) should be 64 bytes in size.

Lastly, OTRv4 uses Ed448 as the cryptographic primitive. This changes the way
values are serialized and how they are computed. To define the SMP values
under Ed448, we reuse the previously defined generator `G1` for ElGamal:

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

* Validates that `G2a` and `G3a` are on the curve Ed448, in the correct group
  and that they do not degenerate.
* Picks random values `b2` and `b3` in `Z_q`.
* Picks random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`.
* Computes `G2b = G1 * b2` and `G3b = G1 * b3`.
* Computes `c2 = HashToScalar(3 || G1 * r2)` and `d2 = r2 - b2 * c2`.
* Computes `c3 = HashToScalar(4 || G1 * r3)` and `d3 = r3 - b3 * c3`.
* Computes `G2 = G2a * b2` and `G3 = G3a * b3`.
* Computes `Pb = G3 * r4` and `Qb = G1 * r4 + G2 * y`, where y is the 'actual
  secret'.
* Computes `cp = HashToScalar(5 || G3 * r5 || G1 * r5 + G2 * r6)`, `d5 = r5 - r4 * cp`
  and `d6 = r6 - y * cp`.
* Sends Alice a SMP message 2 with `G2b`, `c2`, `d2`, `G3b`, `c3`, `d3`, `Pb`,
  `Qb`, `cp`, `d5` and `d6`.

**Alice:**

* Validates that `G2b` and `G3b` are on the curve Ed448, in the correct group
  and that they do not degenerate.
* Computes `G2 = G2b * a2` and `G3 = G3b * a3`.
* Picks random values `r4`, `r5`, `r6` and `r7` in `Z_q`.
* Computes `Pa = G3 * r4` and `Qa = G1 * r4 + G2 * x`, where x is the 'actual
  secret'.
* Computes `cp = HashToScalar(6 || G3 * r5 || G1 * r5 + G2 * r6)`, `d5 = r5 - r4 * cp`
  and `d6 = r6 - x * cp`.
* Computes `Ra = (Qa - Qb) * a3`.
* Computes `cr = HashToScalar(7 || G1 * r7 || (Qa - Qb) * r7)` and `d7 = r7 - a3 * cr`.
* Sends Bob a SMP message 3 with `Pa`, `Qa`, `cp`, `d5`, `d6`, `Ra`, `cr` and `d7`.

**Bob:**

* Validates that `Pa`, `Qa`, and `Ra` are on the curve Ed448, in the correct
  group and that they do not degenerate.
* Picks a random value `r7` in `Z_q`.
* Computes `Rb = (Qa - Qb) * b3`.
* Computes `Rab = Ra * b3`.
* Computes `cr = HashToScalar(8 || G1 * r7 || (Qa - Qb) * r7)` and `d7 = r7 - b3 * cr`.
* Checks whether `Rab == Pa - Pb`.
* Sends Alice a SMP message 4 with `Rb`, `cr`, `d7`.

**Alice:**

* Validates that `Rb` is on curve Ed448, in the correct group and that they do
  not degenerate.
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
integer followed by one or two Points is taken. This is defined as `HashToScalar(d)`.

The input to this hash function is:

```
Version (BYTE)
  This distinguishes calls to the hash function at different points in the
  protocol, to prevent Alice from replaying Bob's zero knowledge proofs or
  vice versa.

First Point (POINT)
  The first Point given as input, encoded in the usual way.

Second Point (POINT)
  The second Point given as input, if present, encoded in the usual way. If
  only one Point is given as input, this field is simply omitted.
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

1. Validate that `G2a` and `G3a` are on curve Ed448, in the correct group and
   that they do not degenerate.
2. Determine Bob's secret input `y`, which is to be compared to Alice's secret
   `x`.
3. Pick random values `b2` and `b3` in `Z_q`. These will used for creating
   generators.
4. Pick random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`. These
   will be used to add a blinding factor to the final results, and to generate
   zero-knowledge proofs that this message was created honestly.
5. Compute `G2b = G1 * b2` and `G3b = G * b3`.
6. Generate a zero-knowledge proof that the value `b2` is known by setting
`c2 = HashToScalar(3 || G1 * r2)` and `d2 = r2 - b2 * c2 mod q`.
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

1. Validate that `G2b`, `G3b`, `Pb`, and `Qb` are on curve Ed448 and that they
   do not degenerate.
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

1. Validate that `Pa`, `Qa`, and `Ra` are on curve Ed448 and that they do not
   degenerate.
2. Pick a random value `r7` in `Z_q`. This will be used to generate
Bob's final zero-knowledge proof that this message was created honestly.
3. Compute `Rb = (Qa - Qb) * b3`.
4. Generate a zero-knowledge proof that `Rb` was created according to the
   protocol by setting
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
  1. Check that both `G2a` and `G3a` are on curve Ed448 and that they do not
     degenerate.
  2. Check that `c2 = HashToScalar(1 || G1 * d2 + G2a * c2)`.
  3. Check that `c3 = HashToScalar(2 || G1 * d3 + G3a * c3)`.
* Create a SMP message 2 and send it to Alice.
* Set smpstate to `SMPSTATE_EXPECT3`.

#### Receiving a SMP message 2

If smpstate is not `SMPSTATE_EXPECT2`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT2`:

* Verify Bob's zero-knowledge proofs for `G2b`, `G3b`, `Pb` and `Qb`:
    1. Check that `G2b`, `G3b`, `Pb` and `Qb` are on curve Ed448 and that they
       do not degenerate.
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
  1. Check that `Pa`, `Qa` and `Ra` are on curve Ed448 and that they do not
     degenerate.
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

  `cr = HashToScalar(8 || G1 * r7 || (Qa - Qb) * r7)` and `d7 = r7 - b3 * cr mod q`.

#### Receiving a SMP message 4

If smpstate is not `SMPSTATE_EXPECT4`:
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is SMPSTATE_EXPECT4:

* Verify Bob's zero-knowledge proof for Rb:
   1. Check that `Rb` is on curve Ed448 and that it does not degenerate.
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
an interface to produce forged transcripts with the same functions used for
honest conversations. This section will guide implementers to achieve this.
The major utilities are:

```
Parse
  Parses OTR messages to the values of each of the fields in
  a message. Parse will reuse the message parsing functionality of the spec.

Modify Data Message
  If an encrypted data message cannot be read because we don't
  know the message key (or a key used to derive this message key) but it can
  be guessed that the string `x` appears at a given offset in the message,
  this method will replace the old text with some new desired text with
  the same length. For example, if the string "hi" is accurately guessed
  to be at the beginning of an encrypted message, it can be replaced with the
  string "yo". In that way, a cryptographically valid data message can be
  created with the new text.

  To achieve this, the XOR of the old text and the new text is XORed
  again with the original encrypted message starting at the given offset.
  After replacing parts of the encrypted message, the MAC tag is recalculated
  with the revealed MAC key associated with this message number. Then the
  new tag is attached to the data message, replacing the old value. A pseudocode
  is included at the appendix.

  Modify Data Message reuses the spec function:

    1. MAC tag creation.

Read and Forge
  Read and forge allows someone in possession of a chain key to decrypt OTR
  messages or modify them as forgeries. It takes three inputs: the chain key,
  the OTR message and an optional new plain text message. If the new message is
  included, the original text is replaced with the new message, and then a new
  MAC tag, based on the new message is attached to the data message. This new
  message is then displayed.

  Read and Forge reuses the spec functions:

    1. Message parser
    2. Decryption of a data message
    3. MAC tag creation.

Forge AKE and Session Keys
  Any participant of an OTR conversation may forge an AKE with another
  participant as long as they have their profile. This function will take the
  profile and the secret long term key of one participant and the profile of
  another.
  It will then return an AKE transcript between the two parties. The
  participant's private key is required since it is used to authenticate the key
  exchange, but the resulting transcript is created in such a way that a
  cryptographic expert cannot identify which profile owner authenticated the
  conversation.

  This forging utility reuses the spec functions:

    1. Create a Identity message
    2. Create a DRE-Auth message

Show MAC Key
  This function takes a chain key and a message key number and shows the mac key
  associated with those two values. For example, if the message key number is 3,
  the message key is ratcheted 3 times, and the third mac key is returned. 'Show
  MAC key' may be used with the ReMAC message in the case where a chain key has
  been compromised by an attacker, and the attacker wishes to forge messages.
  Functionalities around deriving the MAC keys may be used to implement this
  function.

ReMAC Message
  ReMAC Message will create a new OTRv4 Data Message from the input: new MAC
  key, sender instance tag, receiver instance tag, flags, ratchet id, message
  id, public ECDH Key, public DH key, nonce, encrypted message, and revealed MAC
  keys. This function will use the input to create a new Data Message and create
  a new authenticator for this message with the new MAC key provided. An
  attacker may use this function to forge messages with a compromised MAC key.
  Functionalities around creating MAC tags may be reused to implement this
  function.

Forge Entire Transcript
  The Forge Entire Transcript function will allow one participant to completely
  forge a transcript between them and another person in a way that its forgery
  cannot be cryptographically proven. The input will be: one participant's
  profile, their secret key, another person's profile, and a list of plain text
  messages corresponding to what messages were exchanged. Each message in the
  list will have the structure: 1) sender 2) plain text message, so that the
  function may precisely create the desired transcript. The participant's
  private key is required since it is used to authenticate the key exchange, but
  the resulting transcript is created in such a way that a cryptographic expert
  cannot identify which profile owner authenticated the conversation.

  This forging utility reuses the spec functions:

    1. Create an Identity message
    2. Create a DRE-Auth message
    3. Create an encrypted data message
    4. The protocol state machine
```

## Appendices

### SNIZKPK Authentication

The Authentication scheme consists of two functions:

`sigma = Auth(A_1, a_1, {A_1, A_2, A_3}, m)`, an authentication function.

`Verify({A_1, A_2, A_3}, sigma, m)`, a verification function.

#### Domain parameters

We reuse the previously defined G1 generator in ElGamal of DRE:

```
G1 = (11781216126343694673728248434331006466518053535701637341687908214793940427
7809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf393
2d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)
```

#### Authentication: Auth(A1, a1, {A1, A2, A3}, m):

A1 is the public value associated with a1, that is, `A1 = G1*a1`.
m is the message to authenticate.

`A1`, `A2`, and `A3` should be checked to verify they are on curve Ed448.

1. Pick random values `t1, c2, c3, r2, r3` in Z_q.
2. Compute `T1 = G1 * t1`.
3. Compute `T2 = G1 * r2 + A2 * c2`.
4. Compute `T3 = G1 * r3 + A3 * c3`.
5. Compute `c = HashToScalar(G1 || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Compute `c1 = c - c2 - c3 (mod q)`.
7. Compute `r1 = t1 - c1 * a1 (mod q)`.
8. Send `sigma = (c1, r1, c2, r2, c3, r3)`.

#### Verification: Verify({A1, A2, A3}, sigma, m)

`A1`, `A2`, and `A3` should be checked to verify they are on curve Ed448.

1. Parse sigma to retrieve components `(c1, r1, c2, r2, c3, r3)`.
2. Compute `T1 = G1 * r1 + A1 * c1`
3. Compute `T2 = G1 * r2 + A2 * c2`
4. Compute `T3 = G1 * r3 + A3 * c3`
5. Compute `c = HashToScalar(G1 || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Check if `c ≟ c1 + c2 + c3 (mod q)`.

### HashToScalar

This function is `hashToScalar(d)`: d is an array of bytes.

1. Compute `h = SHA3-512(d)` as an unsigned value, big-endian.
2. Return `h (mod q)`

### Modify an encrypted data message

In this example, a forger guesses that "hi" is at the beginning of an encrypted
message. Thus, its offset is 0. The forger wants to replace "hi" with "yo".

  ```
  offset = 0
  old_text = "hi"
  new_text = "yo"
  text_length = string_length_of("hi")
  encrypted_message_length = get_from_data_message()
  old_encrypted_message = get_from_data_message()

  for (i=0; i < text_length && offset+i < encrypted_message_length; i++) {
      old_encrypted_message[offset+i] ^= old_text[i] ^ new_text[i]
  }

  new_encrypted_message = old_encrypted_message

  new_mac_tag = mac(new_encrypted_message, revealed_mac_key)

  new_data_message = replace(old_data_message, new_encrypted_message, new_mac_tag)

  ```

### OTRv3 Specific Encoded Messages

#### D-H Commit Message

This is the first message of OTRv3 AKE. Bob sends it to Alice to commit to a
choice of D-H encryption key (but the key itself is not yet revealed). This
allows the secure session id to be much shorter than in OTRv1, while still
preventing a man-in-the-middle attack on it.

It consists of: the protocol version, the message type, the sender's instance
tag, the receiver's instance tag, the encrypted sender's private key and the
hashed sender's private key.

#### D-H Key Message

This is the second message of OTRv3 AKE. Alice sends it to Bob.

It consists of: the protocol version, the message type, the sender's instance
tag, the receiver's instance tag, the revealed key, the encrypted signature and
and the MAC of the signature.

#### Receiving a D-H Commit Message

If the message is version 3 and version 3 is not allowed, ignore the message.
Otherwise:

If authstate is `AUTHSTATE_NONE`:

  * Reply with a `D-H Key Message`, and transition authstate to
    `AUTHSTATE_AWAITING_REVEALSIG`.

If authstate is `AUTHSTATE_AWAITING_DHKEY`:
  * This indicates that you have already sent a `D-H Commit message` to your
    peer, but that it either didn't receive it, or just didn't receive it yet
    and has sent you one as well. The symmetry will be broken by comparing the
    hashed `gx` you sent in your `D-H Commit Message` with the one you received,
    considered as 32-byte unsigned big-endian values.

  * If yours is the higher hash value:
    * Ignore the incoming `D-H Commit message`, but resend your
      `D-H Commit message`.

  * Otherwise:
    * Forget the old encrypted `gx` value that you sent earlier, and pretend
      you're in `AUTHSTATE_NONE`. For example, reply with a `D-H Key Message`,
      and transition `authstate` to `AUTHSTATE_AWAITING_REVEALSIG`.

If authstate is `AUTHSTATE_AWAITING_REVEALSIG`:
  * Retransmit your `D-H Key Message` (the same one you sent when you entered
    `AUTHSTATE_AWAITING_REVEALSIG`). Forget the old `D-H Commit message` and
    use this new one instead.
    There are a number of reasons this might happen, including:

    * Your correspondent simply started a new AKE.
    * Your correspondent resent his `D-H Commit message`, as specified above.
    * On some networks, like AIM, if your correspondent is logged in multiple
      times, each of his clients will send a `D-H Commit Message` in response
      to a Query Message. Resending the same `D-H Key Message` in response to
      each of those messages will prevent confusion, since each of the clients
      will see each of the `D-H Key Messages` sent.

If authstate is `AUTHSTATE_AWAITING_SIG`:
  * Reply with a new `D-H Key message` and transition authstate to
    `AUTHSTATE_AWAITING_REVEALSIG`.

#### Receiving a D-H Key Message

If the message is version 3 and version 3 is not allowed, ignore this message.
Otherwise:

If authstate is `AUTHSTATE_AWAITING_DHKEY`:
  * Reply with a `Reveal Signature Message` and transition authstate to
    `AUTHSTATE_AWAITING_SIG`.

If authstate is `AUTHSTATE_AWAITING_SIG`:

  * If this `D-H Key message` is the same you received earlier (when you entered
    `AUTHSTATE_AWAITING_SIG`):
    * Retransmit your `Reveal Signature Message`.

  * Otherwise:
    * Ignore the message.

If authstate is `AUTHSTATE_NONE`, `AUTHSTATE_AWAITING_REVEALSIG`, or
`AUTHSTATE_V1_SETUP`:
  * Ignore the message.

#### Receiving a Signature Message

If version 3 is not allowed, ignore this message. Otherwise:

If authstate is AUTHSTATE_AWAITING_SIG:
  * Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:

    * Transition authstate to AUTHSTATE_NONE.
    * Transition msgstate to MSGSTATE_ENCRYPTED.
    * If there is a recent stored message, encrypt it and send it as a Data Message.

  * Otherwise, ignore the message.
If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_DHKEY or AUTHSTATE_AWAITING_REVEALSIG:
  * Ignore the message.

#### Receiving a Reveal Signature Message

If version 3 is not allowed, ignore this message. Otherwise:

If authstate is AUTHSTATE_AWAITING_REVEALSIG:
  * Use the received value of r to decrypt the value of gx received in the D-H Commit Message, and verify the hash therein.
  * Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:

    * Reply with a Signature Message.
    * Transition authstate to AUTHSTATE_NONE.
    * Transition msgstate to MSGSTATE_ENCRYPTED.
    * If there is a recent stored message, encrypt it and send it as a Data Message.

  * Otherwise, ignore the message.
If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_DHKEY or AUTHSTATE_AWAITING_SIG:
  * Ignore the message.

#### Reveal Signature Message

This is the third message of the OTRv3 AKE. Bob sends it to Alice, revealing his D-H
encryption key (and thus opening an encrypted channel), and also authenticating
himself (and the parameters of the channel, preventing a man-in-the-middle
attack on the channel itself) to Alice.

It consists of: the protocol version, the message type, the sender's instance
tag, the receiver's instance tag, the encrypted signature and the MAC of the
signature

#### Signature Message

This is the final message of the OTRv3 AKE. Alice sends it to Bob,
authenticating herself and the channel parameters to him.

It consists of: the protocol version, the message type, the sender's instance
tag, the receiver's instance tag, the encrypted signature and the MAC of the
signature.

#### Sending a TLV type 1 (Disconnect) Message

If the user requests to close its private connection, you may send
a message (possibly with an empty human-readable part) containing a record
with TLV type 1 just before you discard the session keys. You should then
transition to 'MSGSTATE_PLAINTEXT'.

### OTRv3 Protocol State Machine

OTRv3 defines three main state variables:

#### Message state

The message state variable `msgstate` controls what happens to outgoing messages
typed by the user. It can take one of three values:

```
MSGSTATE_PLAINTEXT
  This state indicates that outgoing messages are sent without encryption. This
  is the state used before an OTRv3 conversation is initiated. This is the
  initial state, and the only way to subsequently enter this state is for the
  user to explicitly request so via some UI operation.

MSGSTATE_ENCRYPTED
  This state indicates that outgoing messages are sent encrypted. This is the
  state that is used during an OTRv3 conversation. The only way to enter this
  state is when the authentication state machine (below) is completed.

MSGSTATE_FINISHED
  This state indicates that outgoing messages are not delivered at all. This
  state is entered only when the other party indicates that its side of the
  conversation has ended. For example, if Alice and Bob are having an OTR
  conversation, and Bob instructs his OTR client to end its private session with
  Alice (for example, by logging out), Alice will be notified of this, and her
  client will switch to 'MSGSTATE_FINISHED' mode. This prevents Alice from
  accidentally sending a message to Bob in plaintext (consider what happens if
  Alice was in the middle of typing a private message to Bob when he suddenly
  logs out, just as Alice hits Enter.)
```

#### Authentication state

The authentication state variable `authstate` can take one of four values:

```
AUTHSTATE_NONE
  This state indicates that the authentication protocol is not currently in
  progress. This is the initial state.

AUTHSTATE_AWAITING_DHKEY
  After Bob initiates the authentication protocol by sending Alice the 'D-H
  Commit Message', he enters this state to await Alice's reply.

AUTHSTATE_AWAITING_REVEALSIG
  After Alice receives Bob's D-H Commit Message, and replies with her own 'D-H
  Key Message', she enters this state to await Bob's reply.

AUTHSTATE_AWAITING_SIG
  After Bob receives Alice's 'D-H Key Message', and replies with his own Reveal
  Signature Message, he enters this state to await Alice's reply.

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
