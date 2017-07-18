# OTR version 4

OTR version 4 (OTRv4) provides a deniable authenticated key
exchange and better forward secrecy through the use of double ratcheting. OTR
works on top of an existing messaging protocol, like XMPP.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)
1. [High Level Overview](#high-level-overview)
1. [Assumptions](#assumptions)
1. [Security Properties](#security-properties)
1. [Notation and parameters](#notation-and-parameters)
   1. [Notation](#notation)
   1. [Elliptic Curve Parameters](#elliptic-curve-parameters)
   1. [3072-bit Diffie-Hellman Parameters](#L3072-bit-diffie-hellman-parameters)
1. [Data Types](#data-types)
   1. [Encoding and Decoding](#encoding-and-decoding)
   1. [Serializing the SNIZKPK Authentication](#serializing-the-snizkpk-authentication)
   1. [Public keys and fingerprints](#public-keys-and-fingerprints)
   1. [TLV Record Types](#tlv-record-types)
   1. [Shared session state](#shared-session-state)
   1. [OTR Error Messages](#otr-error-messages)
1. [Key management](#key-management)
   1. [Generating ECDH and DH keys](#generating-ecdh-and-dh-keys)
   1. [Shared secrets](#shared-secrets)
   1. [Key derivation functions](#key-derivation-functions)
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
   1. [Interactive Deniable Authenticated Key Exchange (DAKE)](#interactive-deniable-authenticated-key-exchange--dake-)
1. [Offline Conversation Initialization](#offline-conversation-initialization)
   1. [Non-interactive Deniable Authenticated Key Exchange (DAKE)](#non-interactive-deniable-authenticated-key-exchange--dake-)
   1. [Prekey Message](#prekey-message)
   1. [Validating a Prekey Message](#validating-a-prekey-message)
   1. [Non-interactive Auth Message](#non-interactive-auth-message)
   1. [Publishing prekeys](#publishing-prekeys)
   1. [Obtaining prekeys](#obtaining-prekeys)
1. [Data Exchange](#data-exchange)
   1. [Data Message](#data-message)
   1. [Revealing MAC Keys](#revealing-mac-keys)
1. [Fragmentation](#fragmentation)
   1. [Transmitting Fragments](#transmitting-fragments)
   1. [Receiving Fragments](#receiving-fragments)
1. [The protocol state machine](#the-protocol-state-machine)
   1. [Protocol states](#protocol-states)
   1. [Protocol events](#protocol-events)
1. [Socialist Millionaires Protocol (SMP)](#socialist-millionaires-protocol--smp-)
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
  - Deniable authenticated key exchanges using DAKEZ and XZDH [\[1\]](#references).
    DAKEZ corresponds to online conversations and XZDH to offline conversations.
  - Key management using the Double Ratchet Algorithm [\[2\]](#references).
  - Upgraded SHA-1 and SHA-2 to SHA-3.
  - Switched from AES to XSalsa20.
- Explicit instructions for producing forged transcripts using the same
  functions used to conduct honest conversations.

Reasons for the decisions made above and more are included in the [architectural
decisions records](https://github.com/twstrike/otrv4/tree/master/architecture-decisions).

## High Level Overview

An OTRv4 conversation may begin when the two participants are online (an
interactive conversation) or when one participant is offline (non-interactive
conversation).

### Conversation started by an Interactive DAKE

```
Alice                                            Bob
--------------------------------------------------------------------------------
Requests OTR conversation           ------------->

Establishes Conversation with       <------------>  Establishes Conversation with
Deniable Authenticated Key Exchange                 Deniable Authenticated Key Exchange

Exchanges Data Messages             <------------>  Exchanges Data Messages
```

The conversation can begin after one participant requests a conversation. This
includes an advertisement of which versions they support. If the other
participant supports OTRv4, an interactive, DAKE can be used to establish a
secure channel. Encrypted messages are then exchanged in this secure channel
with forward secrecy.

### Conversation started by a Non-Interactive DAKE

```
Alice                        Prekey Server                  Bob
--------------------------------------------------------------------------------
                                    (<--------------------- Pre-conversation: Creates
                                                            and sends a Prekey Message)
Retrieves Bob's  ----------------->
Prekey Message

Establishes Non-interactive ------------------------------->
Conversation with Bob and
sends the first Data Message

Exchanges Data Messages <---------------------------------->  Exchanges Data Messages

```

In this conversation flow, Alice first retrieves a Prekey message from a prekey
server. This prekey message was uploaded by Bob's client prior to the start of
the conversation to allow other participants, like Alice, to send him encrypted
messages while he is offline.

## Assumptions

Messages in a conversation can be exchanged over an insecure channel, where an
attacker can eavesdrop or interfere with the encrypted messages.

The network model provides in-order delivery of messages, and some messages
may not be delivered.

OTRv4 does not protect against an active attacker performing Denial of Service
attacks to reduce availability.

## Security Properties

OTRv4 does not take advantage of quantum resistant algorithms for several
reasons. Mainly, OTRv4 aims to be a protocol that is easy to implement in
today's environments within a year. Current quantum resistant algorithms and
their respective implementations are not ready enough to allow for this
implementation time frame. As a result, the protections mentioned in the
following paragraphs only apply to non-quantum adversaries.

The only exception is the usage of a "mix key" to provide
some post-conversation transcript protection against potential weaknesses with
elliptic curves and the early arrival of quantum computers.

In the interactive DAKE, although access to one participant's private long term
key is required for authentication, both participants can deny having used
their private long term keys. An external cryptographic expert will be able to
prove that one person between the two used their long term private key for the
authentication, but they will not be able to identify whose key was used. In
the case where an adversary has compromised one of the long term private keys,
a cryptographic expert cannot prove whether the DAKE was forged by the
adversary or legitimately created by the non-compromised participant. This
provides deniability for both participants in the interactive DAKE.

In the non-interactive DAKE, the initializer (Alice, in the above overview) does
not have participation deniability, but Bob, the receiver, does.

Once a channel has been created with the DAKE, all data messages transmitted
through this channel are confidential and have integrity. After a MAC key is
used to validate a received message, it is revealed in the first message sent
in the next ratchet. This allows for forgeability of the data messages and
consequent deniability of their contents.

If key material used to encrypt a particular data message is compromised,
previous messages are protected. Additionally, future messages are protected by
the Diffie-Hellman and Elliptic Curve Diffie-Hellman ratchets.

## Notation and parameters

This section contains information needed to understand the parameters,
variables and arithmetic used in the specification.

### Notation

Scalars and secret keys are in lower case, such as `x` or `y`. Points and
public keys are in upper case, such as `P` or `Q`.

Addition of elliptic curve points `A` and `B` is `A + B`. Subtraction is `A -
B`. Addition of a point to another point generates a third point. Scalar
multiplication of an elliptic curve point `B` with a scalar `a` yields a new
point: `C = B * a`.

The concatenation of byte sequences `I` and `J` is `I || J`. In this case, `I`
and `J` represent a fixed-length byte sequence encoding the respective values.
See the section on [Data Types](#data-types) for encoding and decoding details.

### Elliptic Curve Parameters

OTRv4 uses the Ed448-Goldilocks [\[3\]](#references) elliptic curve
[\[4\]](#references), which defines the following parameters:

```
Equation
	x^2 + y^2 = 1 - 39081 * x^2 * y^2

Coordinates:
	Edwards

Base point (G)
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

Order of base point (q) [prime; q < p; q * G = I]
  2^446 - 13818066809895115352007386748515426880336692474882178609894547503885

Non-square element in Z_p (d)
  -39081
```

A scalar modulo `q` is a field element, and should be encoded and decoded
as a SCALAR type, which is defined in the [Data Types](#data-types) section.

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

Whenever you see an operation on a field element from this group, the
operation should be done modulo the prime `dh_p`.

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
  57 bytes data

Ed448 scalar (SCALAR):
  56 bytes data

User Profile (USER-PROF):
  Detailed in "User Profile Data Type" section
```

In order to encode and decode `POINT` and `SCALAR` types, refer to the [Encoding and
Decoding](#encoding-and-decoding) section.

### Encoding and Decoding

We follow the encoding and decoding schemes specified in RFC 8032 [\[17\]](#references).

#### Scalar

Encoded as a little-endian array of 56 bytes, e.g.
`h[0] + 2^8 * h[1] + ... + 2^448 * h[55]`.

#### Point

A curve point `(x,y)`, with coordinates in the range `0 <= x,y < p`, is
encoded as follows:

1. Encode the y-coordinate as a little-endian array of 57 bytes. The
   final byte is always zero.
2. Copy the least significant bit of the x-coordinate to the most
   significant bit of the final byte. This is 1 if the x-coordinate is
   negative or 0 if it is not.

A curve point is decoded as follows:

1. Interpret last bit of byte 57 as the least significant bit of the x-coordinate.
   Denote this value `x_0`.  The y-coordinate is recovered simply by
   clearing this bit.  If the resulting value is `>= p`, decoding fails.
2. To recover the x-coordinate, the curve equation implies
   `x^2 = (y^2 - 1) / (d * y^2 - 1) (mod p)`.  The denominator is always
   non-zero mod p.
   1. Let `num = y^2 - 1` and `denom = d * y^2 - 1`.  To compute the square root
      of `(num/denom)`, compute the candidate root `x = (num/denom)^((p+1)/4)`.
      This can be done using a single modular powering for both the
      inversion of `denom` and the square root:
      ```
           x = ((num ^ 3) * denom * (num^5 * num^3) ^ ((p-3)/4)) (mod p)
      ```

   3.  If `denom * x^2 = num`, the recovered x-coordinate is `x`.  Otherwise, no
       square root exists, and the decoding fails.
3. Use the `x_0` bit to select the right square root.  If `x = 0`, and
   `x_0 = 1`, decoding fails.  Otherwise, if `x_0 != x mod 2`, set
   `x <-- p - x`.  Return the decoded point `(x,y)`.


### Serializing the SNIZKPK Authentication

A signature non-interactive zero-knowledge proof of knowledge (SNIZKPK) is
serialized as follows:

```
SNIZKPK Authentication (SNIZKPK):
  c1 (SCALAR)
  r1 (SCALAR)
  c2 (SCALAR)
  r2 (SCALAR)
  c3 (SCALAR)
  r3 (SCALAR)
```
### Public keys and fingerprints

OTRv4 introduces a new type of public key:

```
OTR4 public authentication Ed448 key (ED448-PUBKEY):

  Pubkey type (SHORT)
    Ed448 public keys have type 0x0010

    H (POINT)
      H is the Ed448 public key generated as defined in RFC 8032.
```

Public keys have fingerprints, which are hex strings that serve as
identifiers for the public key. The fingerprint is calculated by taking the
SHA3-512 hash of the byte-level representation of the public key.

For generation of the public key, refer to RFC 8032 [\[17\]](#references),
section 5.2.5.

The public key is generated as follows:

```
The symmetric key is 57 bytes of cryptographically secure random data.

1. Hash the 57-byte symmetric key using SHAKE256(symmetric). Store the
   digest in a 114-bytes large buffer, denoted 'h'.  Only the lower 57 bytes
   are used for generating the public key.
// TODO: this is clamping. State it somewhere?
2. Prune the buffer: the two least significant bits of the first
   octet are cleared, all eight bits the last octet are cleared, and the
   highest bit of the second to last octet is set.
// TODO: include the base point.
3. Interpret the buffer as the little-endian integer, forming a
   secret scalar 's'.  Perform a known-base-point scalar multiplication s *
   Base_point'. Let 'H' be the result of this multiplication.
```

### TLV Record Types

Each TLV record is of the form:

```
Type (SHORT)
  The type of this record. Records with unrecognized types should be ignored
Length (SHORT)
  The length of the following field
Value (len BYTE) [where len is the value of the Length field]
  Any pertinent data for the record type
```

OTRv4 supports some TLV record types from OTRv3. The supported types are:
```
Type 0: Padding
  The value may be an arbitrary amount of data. This data should be ignored.
  This type can be used to disguise the length of a plaintext message.

Type 1: Disconnected
  Closes the connection.

Type 2: SMP Message 1
  The value represents the initial message of the Socialist Millionaires'
  Protocol (SMP), described below (in Socialist Millionaires Protocol (SMP)).
  Note that this represents TLV type 1 and 7 from OTRv3.

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
  you should change the SMP state to 'SMP_EXPECT1' (see below in SMP section).

Type 8: Extra symmetric key
  If you wish to use the extra symmetric key, compute it yourself as outlined
  in the section "Extra symmetric key". Then send this type 8 TLV to your peer
  to indicate that you'd like to use the extra symmetric key for something. The
  value of the TLV begins with a 4-byte indication of what this symmetric key
  will be used for (file transfer, voice encryption, etc). After that, the
  contents are use-specific (which file, etc): there are no predefined uses.
  Note that the value of the key itself is not placed into the TLV; your peer
  will compute it on its own.
```

### Shared Session State

Each of the two DAKEs must authenticate its context to prevent attacks that
rebind the DAKE transcript into different contexts. If the higher-level
protocol ascribes some property to the connection, the DAKE exchange should
verify this property. Given the share dession state information `phi`
associated with the higher-level context (e.g., a session identifier), the DAKE
authenticates that both parties share the same value for `phi`.

The shared session state (Φ) is any session-specific protocol state available to
both parties in the higher-level protocol. For example, in XMPP, it will be the
node and domain identifiers of the Jabber identifier, e.g. alice@jabber.net.

### OTR Error Messages

Any message containing the string "?OTR Error:" is an OTR Error Message. The
following part of the message should contain human-readable details of the
error. The message may also include a specific code at the beginning, e.g. "?OTR
Error: ERROR_N:". This code is used to identify which error is being
received for optional localization of the message.

Error Code List:

```
  ERROR_1:
    Message cannot be decrypted
```

## Key Management

In both the interactive and non-interactive DAKEs, OTRv4 uses long-term Ed448 keys, ephemeral Elliptic
Curve Diffie-Hellman (ECDH) keys, and ephemeral Diffie-Hellman (DH) keys.

For exchanging data messages, OTRv4 uses both the DH ratchet (with
ECDH) and the symmetric-key ratchet from the Double Ratchet algorithm [\[2\]](#references).
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
  'mac_keys_to_reveal': the MAC keys to be revealed in next data message sent.
```

When these events occur, the state variables are incremented and the key variable
values are replaced:

* When you start a new [interactive DAKE](#interactive-dake-overview) by sending or receiving an [Identity message](#identity-message)
* When you complete the [interactive DAKE](#interactive-dake-overview) by sending an [Auth-I Message](#auth-i-message)
* When you complete the [interactive DAKE](#interactive-dake-overview) by receiving and validating an [Auth-I Message](#auth-i-message)
* When you [send a Data Message or receive a Data Message](#data-exchange)
* When you [send a TLV type 1 (Disconnect)](#sending-a-tlv-type-1--disconnect--message)
* When you [receive a TLV type 1 (Disconnect)](#receiving-a-tlv-type-1--disconnect--message)
* When you complete a non-interactive DAKE by [sending a non-interactive auth message](#sending-an-encrypted-message-to-an-offline-participant)
* When you complete a non-interactive DAKE by [receiving and validating a non-interactive auth message](#receiving-a-non-interactive-auth-message)

### Generating ECDH and DH keys

```
generateECDH()
  pick a random value r (57 bytes)
  return our_ecdh.public = G * r, our_ecdh.secret = r

generateDH()
  pick a random value r (80 bytes)
  return our_dh.public = g3 ^ r, our_dh.secret = r
```

### Shared secrets

```
k_dh:
  The 3072-bit DH shared secret computed from a DH exchange, serialized as a big-endian unsigned integer.
  This is serialized as a big-endian unsigned integer.

mix_key:
  A SHA3-256 hash of the shared DH key SHA3-256(k_dh).

K_ecdh:
  The serialized ECDH shared secret computed from an ECDH exchange, serialized as a POINT.

K:
  The mixed shared secret is the final shared secret derived from both the
  DH and ECDH shared secrets.
```

### Key derivation functions

The following key derivation functions are used:

```
KDF_1(x) = SHA3-256("OTR4" || x)
KDF_2(x) = SHA3-512("OTR4" || x)
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
  R = KDF_2(0x01 || K)
  Ca = KDF_2(0x02 || K)
  Cb = KDF_2(0x03 || K)
  return R, decide_between_chain_keys(Ca, Cb)
```

// TODO: is this how the ratchet will behave?
### Rotating ECDH keys and mix key as sender

Before sending the first reply (i.e. a new message considering a previous
message has been received) the sender will rotate their ECDH keys and mix key.
This is for the computation of `K` (see "Deriving Double Ratchet Keys"). The
following data messages will advertise a new ratchet id as `i + 1`.

Before rotating the keys:

  * Increment the current ratchet id (`i`) by 1.
  * Reset the next message id (`j`) to 0.

To rotate the ECDH keys:

  * Generate a new ECDH key pair and assign it to `our_ecdh = generateECDH()`.
  * Calculate `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.
  * Securely delete `our_ecdh.secret`.

To rotate the mix key:

  * If `i % 3 == 0`:

    * Generate the new DH key pair `our_dh = generateDH()`.
    * Calculate `k_dh = DH(our_dh.secret, their_dh.public)`.
    * Calculate a `mix_key = KDF_1(k_dh)`.

  Otherwise:

   * Derive and securely overwrite `mix_key = KDF_1(mix_key)`.

### Rotating ECDH keys and mix key as receiver

Every ratchet, the receiver will rotate their ECDH keys and mix key.
This is for the computation of `K` (see "Deriving Double Ratchet Keys").

Before rotating the keys:

  * Increment the current ratchet id (`i`) by 1.
  * Reset the next message id (`j`) to 0.

To rotate the ECDH keys:

  * Retrieve the ECDH key from the received data message and assign it to their_ecdh.
  * Calculate `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.

To rotate the mix key:

  * If `i % 3 == 0`:

    * Retrieve the DH key from the received data message and assign it to their_dh.
    * Calculate `k_dh = DH(our_dh.secret, their_dh.public)`.
    * Calculate a `mix_key = KDF_1(k_dh)`.
    * Securely delete `our_dh.secret` (this should only be deleted after calculating the new mix key when receiving as new keys will be generated on the next DH rotation).

  Otherwise:

   * Derive and securely overwrite `mix_key = KDF_1(mix_key)`.

### Deriving new chain keys

When sending data messages, you must derive the chain key:

```
derive_chain_key(C, i, j):
  C[i][j] = KDF_2(C[i][j-1])
  return C[i][j]
```

### Computing chain keys

When receiving data messages, you must compute the chain key:

```
compute_chain_key(C, i, k):
  if C[i][k] does not exist:
    C[i][k] = KDF_2(compute_chain_key(C, i, k-1))
  return C[i][k]
```

### Calculating encryption and MAC keys

When sending or receiving data messages, you must calculate the message keys:

```
derive_enc_mac_keys(chain_key):
  MKenc = take_first_256_bits(KDF_2(0x01 || chain_key))
  MKmac = KDF_2(0x02 || chain_key)
  return MKenc, MKmac
```

### Resetting state variables and key variables

The state variables are set to `0` and the key variables are set to `NIL` for
this channel.

## User Profile

OTRv4 introduces a user profile. The user profile contains the Ed448 long term
public key, a shared prekey for offline conversations, information about
supported versions, a profile expiration date, a signature of all these, and an
optional transition signature.

Each participant maintains two instances of the same user profile. One instance
is for authentication in both DAKEs. The other instance is for publication. A
user is allowed to repudiate their participation in OTRv4 conversations by
publishing their user profile.  When a user profile is published, it is
available from a public location, such as a server.

Each implementation may decide how to publish the profile. For example, one
client may publish profiles to a server pool (similar to a keyserver pool,
where PGP public keys can be published). Another client may use XMPP's publish-
subscribe extension (XEP-0060 [\[8\]](#references)) for publishing profiles. A
protocol for publication must be defined, but the definition is out of scope
for this specification.

When the user profile expires, it should be updated. Client implementation
should determine the frequency of user's profile expiration and renewal. The
recommended expiration time is two weeks.

### Creating a User Profile

To create a user profile, assemble:

1. User's Ed448 long term public key.
2. Versions: a string corresponding to the user's supported OTR versions.
   A user profile can advertise multiple OTR versions. The format is described
   under the section [Establishing Versions](#establishing-versions) below.
3. Profile Expiration: Expiration date in standard Unix 64-bit format
   (seconds since the midnight starting Jan 1, 1970, UTC, ignoring leap
   seconds).
4. Public Shared Prekey: An Ed448 Point used in multiple prekey messages. It adds some
   protection against attacker modification of the first flow of the non-interactive
   DAKE.
5. Profile Signature: The secret key value (`r`) of the Ed448 long term public
   key and a flag `F` (set to zero, as defined on [RFC]8032) are used to create
   signatures of the entire profile excluding the signature itself. The size of
   the signature is 114 bytes.
6. Transition Signature (optional): A signature of the profile excluding Profile
   Signatures and the user's OTRv3 DSA key. The Transition Signature enables
   contacts that trust user's version 3 DSA key to trust the user's profile in
   version 4. This is only used if the user supports versions 3 and 4.

After the profile is created, it must be published in a public place, like an
untrusted server.

### Establishing Versions

A valid versions string can be created by concatenating supported version
numbers together in any order. For example, a user who supports versions 3 and 4
will have the 2-byte version string "43" or "34" in their profile. A user who
only supports version 4 will have the 1-byte version string "4". Thus, a version string has
varying size, and it is represented as a DATA type with its length specified.

OTRv4 supports version 3 of OTR, but not versions 1 and 2. Therefore, invalid version strings contain a "2" or a "1".

Any other version string that is not "4", "3", "2", or "1" should be ignored.

### Profile Expiration and Renewal

If a renewed profile is not published in a public place, the user's
participation deniability is at risk. Participation deniability is also at risk
if the only publicly available profile is expired. In addition, an expired
profile received in the DAKE is considered invalid.

Before the profile expires, the user must publish an updated profile with a
new expiration date. The client establishes the frequency of expiration - this
can be configurable. A recommended value is two weeks.

### Create the Public Shared Prekey

To create a shared prekey, generate and set `our_shared_prekey` as ephemeral ECDH keys:
* secret key `e` (57 bytes) // TODO: is this using the symmetric or the priv?
* public key `E`.

### Create a User Profile Signature

The user profile signature is generated as defined in RFC 8032 section 5.2.6.
The flag `F` is set to `0` and the context `C` is left empty.

```
// TODO: I guess context and flag are not needed to be stated. Just for
compatibility with RCF?
// TODO: change var names and follow the uppercase, lowercase style for points
or scalars
// TODO: note that the secret key is here 57. For the rest of the spec is 56.
// add a note?

The inputs to the signing function are the symmetric key (57 bytes, defined on
Public keys and fingerprints'), a flag 'F', which is 0, and a message 'M' of
arbitrary size.

   1.  Hash the symmetric key: 'SHAKE256(symmetric)'.  Store the first 114 bytes
       of the digest on 'h'. Construct the secret key 's' from
       the first half of the digest (57 bytes), and the corresponding public
       key 'H', as defined on 'Public keys and fingerprints' section.
       Let 'nonce' denote the second half of the hash digest (from
       h[57] to h[113]).

   2.  Compute SHAKE256("SigEd448" || 'nonce' || M). Let 'r' be the 114-byte
       digest.

   // TODO: add the base point of eddsa. Note that this might change. Refer to
   RFC 7748. Check the code.
   3.  Multiply the scalar 'r' by the base point. B.  For efficiency, do this by
       first reducing 'r' modulo 'q', the group order of B.  Let 'nonce_point'
       be the encoding of this point.

   4.  Compute SHAKE256("SigEd448" || 'nonce_point' || H || M). Let 'challenge'
       be the encoded 114-byte digest.

   5.  Compute 'S = (r + 'challenge' * s) mod q'.  For efficiency, reduce
       'challenge' modulo q.

   6.  Form the signature of the concatenation of 'nonce_point' (57 bytes) and
       the little-endian encoding of 'S' (57 bytes, the ten most significant
       bits are always zero).
```

### Verify a User Profile Signature

The user profile signature is verified as defined in RFC 8032 section 5.2.7.

```
1.  To verify a signature on a message 'M' using the public key 'H', with F
    being 0, first split the signature into two 57-byte halves.  Decode the
    first half as a 'nonce_point', and the second half as 'S'. Decode the public
    key 'H' as a point.  If any of the decodings fail (including 'S' being out
    of range), the signature is invalid.
2.  Compute SHAKE256("SigEd448" || 'nonce_point' || H || M). Let 'challenge'
    be the 114-byte encoded digest.
// TODO: does not need to check cofactor, is this ok?
3.  Check the group equation 'S' == 'nonce_point' + 'challenge' * H'.
```

### User Profile Data Type

```
Profile Expiration (PROF-EXP):
  8 bytes signed value, big-endian

User Profile (USER-PROF):
  Ed448 public key (ED448-PUBKEY)
  Versions (DATA)
  Profile Expiration (PROF-EXP)
  Public Shared Prekey (POINT)
    The prekey shared between different prekey messages.
  Profile Signature (EDDSA-SIG)
  (optional) Transitional Signature (SIG)
```

SIG is the OTRv3 DSA Signature (from the protocol section
"Public keys, signatures, and fingerprints"):

```
DSA signature (SIG):
  (len is the length of the DSA public parameter q, which in current
  implementations is 20 bytes)
  len byte unsigned r, big-endian
  len byte unsigned s, big-endian
```

EDDSA-SIG refers to the OTR version 4 signature:

```
EDDSA signature (EDDSA-SIG):
  (len is the expected length of the signature, which is 114 bytes)
  len byte unsigned value, big-endian
```

### Validating a User Profile

To validate a user profile, you must:

* [Verify that the user profile signature is valid](#verify-a-user-profile-signature)
* Verify that the user profile is not expired
* Verify that the `Versions` field contains a string with "4"
* Validate the public shared prekey is on the curve Ed448

## Online Conversation Initialization

Online OTRv4 conversations are initialized through a [Query Message or a
Whitespace Tag](#user-requests-to-start-an-otr-conversation). After this, the
conversation is authenticated using the interactive DAKE.

### Requesting conversation with older OTR versions

Bob might respond to Alice's request (or notification of willingness to start a
conversation) using OTRv3. If this is the case and Alice supports version 3,
the protocol falls back to OTRv3 [\[7\]](#references). If Alice does not
support version 3, this response is ignored.

### Interactive Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the interactive DAKE. This is a way to
mutually agree upon shared keys for the two parties and authenticate one
another while providing participation deniability.

This protocol is derived from the DAKEZ protocol [\[1\]](#references), which
uses a signature non-interactive zero-knowledge proof of knowledge (SNIZKPK)
for authentication (Auth).

Alice's long-term Ed448 key-pair is `(ska, PKa)` and Bob's long-term Ed448
key-pair is `(skb, PKb)`. Both key pairs are generated by `PK = G * sk`.

#### Interactive DAKE Overview

```
Alice                                           Bob
---------------------------------------------------
       Query Message or Whitespace Tag -------->
       <----------------------- Identity message
       DRE-R ---------------------------------->
       <---------------------------------- DRE-I
```

Bob will be initiating the DAKE with Alice.

**Bob:**

1. Generates and sets `our_ecdh` as ephemeral ECDH keys.
2. Generates and sets `our_dh` as ephemeral 3072-bit DH keys.
3. Sends Alice an Identity message.

**Alice:**

1. Receives an Identity message from Bob:
    * Validates Bob's User Profile.
    * Picks a compatible version of OTR listed in Bob's profile.
      If the versions are incompatible, Alice does not send any further
      messages.
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
    * Picks a compatible version of OTR listed on Alice's profile,
      and follows the specification for this version. If the versions are
      incompatible, Bob does not send any further messages.
    * Verify the authentication `sigma` (see [Auth-R message](#auth-r-message)
      section).
    * Verify `(Y, B)` in the message is an Identity message that Bob previously
      sent and has not been used.
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
    * Calculates Mixed shared secret `K = KDF_2(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: it is the first 8 bytes of
      `KDF_2(0x00 || K)`.
    * Calculates the first set of keys with
      `root[0], chain_s[0][0], chain_r[0][0] = derive_ratchet_keys(K)`.
    * [Decides which chain key he will use](#deciding-between-chain-keys).

**Alice:**

1. Receives an Auth-I message from Bob:
    * Verify the authentication `sigma` (see [Auth-I message](#auth-i-message) section).
2. At this point, the interactive DAKE is complete for Alice:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 1.
    * Calculates ECDH shared secret `K_ecdh`.
    * Calculates DH shared secret `k_dh` and `mix_key`.
    * Calculates Mixed shared secret `K = KDF_2(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: the first 8 bytes of
      `KDF_2(0x00 || K)`.
    * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = derive_ratchet_keys(K)`.
    * [Decides which chain key she will use](#deciding-between-chain-keys).

#### Identity message

This is the first message of the DAKE. Bob sends it to Alice to commit to a
choice of DH and ECDH key. A valid Identity message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile).
2. Generate an ephemeral ECDH key pair:
  * secret key `y` (57 bytes).
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
  The instance tag of the intended recipient. For an Identity message, this
  will often be 0 since the other party may not have identified its instance
  tag yet.
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
  * secret key `x` (57 bytes).
  * public key `X`.
3. Generate an ephemeral DH key pair:
  * secret key `a` (80 bytes).
  * public key `A`.
4. Compute `t = 0x0 || SHA3-512(Bobs_User_Profile) || SHA3-512(Alices_User_Profile) || Y || X || B || A || SHA3-512(Φ)`.
   Φ is the shared session state as mention on the 'Shared session state: Phi'
   section.
5. Compute `sigma = Auth(Pka, ska, {Pkb, Pka, Y}, t)`.

To verify an Auth-R message:

1. Validate the user profile, and extract `Pka` from it.
2. Compute `t = 0x0 || SHA3-512(Bobs_User_Profile) || SHA3-512(Alices_User_Profile) || Y || X || B || A || SHA3-512(Φ)`.
   Φ is the shared session state as mention on the 'Shared session state: Phi'
   section.
3. Verify the `sigma` with [SNIZKPK Authentication](#snizkpk-authentication),
that is `sigma == Verify({Pkb, Pka, Y}, t)`.

An Auth-R is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x91.
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

This is the final message of the DAKE. Bob sends it to Alice to verify the
authentification `sigma`.

A valid Auth-I message is generated as follows:

1. Compute `t = 0x1 || SHA3-512(Bobs_User_Profile) || SHA3-512(Alices_User_Profile) || Y || X || B || A || SHA3-512(Φ)`.
   Φ is the shared session state as mention on the 'Shared session state: Phi'
   section.
2. Compute `sigma = Auth(Pkb, skb, {Pkb, Pka, X}, t)`.

To verify the Auth-I message:

1. Compute `t = 0x1 || SHA3-512(Bobs_User_Profile) || SHA3-512(Alices_User_Profile) || Y || X || B || A || SHA3-512(Φ)`.
   Φ is the shared session state as mention on the 'Shared session state: Phi'
   section.
2. Verify the `sigma` with [SNIZKPK Authentication](#snizkpk-authentication),
that is `sigma == Verify({Pkb, Pka, X}, t)`.

An Auth-I is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x88.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient.
sigma (SNIZKPK)
  The SNIZKPK Auth value.
```

## Offline Conversation Initialization

To begin an offline conversation, a prekey message is published to an
unstrusted server and this action is seen as the start of a non-interactive
DAKE. Then, the prekey message is retrieved by the party attempting to send a
message to the publisher. A reply called the non-interactive auth
message is created with the prekey and sent. This completes the DAKE.

The offline DAKE is based on the XZDH protocol [\[1\]](#references). Like the
interactive DAKE, it also uses a SNIZKPK for authentication (Auth).

### Non-interactive Deniable Authenticated Key Exchange (DAKE)

The non-interactive DAKE is a way to mutually agree upon shared cryptographic
keys while providing some participation deniability. Unlike the interactive
DAKE, the non-interactive DAKE does not provide online deniability for the
party that completes the DAKE by sending a non-interactive auth message. Client
implementations are expected to understand the deniability risks when allowing
users to complete a non-interactive DAKE. They are also expected to decide how
to convey this security loss to the user.

This protocol is derived from the XZDH protocol [\[1\]](#references), which
uses a signature non-interactive zero-knowledge proof of knowledge (SNIZKPK)
for authentication (Auth).

Alice's long-term Ed448 key-pair is `(ska, PKa)` and Bob's long-term Ed448
key-pair is `(skb, PKb)`. Both key pairs are generated by `PK = G * sk`.

#### Non-interactive DAKE Overview

```
Bob                         Server                               Alice
----------------------------------------------------------------------
Publish prekey message ---->
								....
                                     <------------ Request prekeys
                                     Prekeys -------------------->
      <---------------------------------------- Non-interactive Auth message
Verify & Decrypt message
```

**Bob:**

1. Generates a [prekey message](#prekey-message).
2. Publishes the prekey message to the untrusted server.

**Alice:**

1. Requests a prekey from the untrusted server.
2. For each prekey message received from the server:
    * Validates Bob's User Profile.
    * Picks a compatible version of OTR listed in Bob's profile.
      If the versions are incompatible, Bob does not send any further
      messages.
    * Validates the received ECDH ephemeral public key is on curve Ed448 and
      sets it as `their_ecdh`.
    * Validates that the received DH ephemeral public key is on the correct
      group and sets it as `their_dh`.
3. Generates and sets `our_ecdh` as ephemeral ECDH keys.
4. Generates and sets `our_dh` as ephemeral 3072-bit DH keys.
5. Sends Bob a non-interactive auth message.

**Bob:**

1. Receive the non-interactive auth message.

### Prekey message

This message is created and published to a prekey server to allow offline
conversations. Each prekey message contains the owner's user profile and two 2
one-time use public prekey values.

It is created as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile).
2. Create the first one-time use prekey by generating the ephemeral
   ECDH key pair:
   * secret key `y` (57 bytes).
   * public key `Y`.
3. Create the second one-time use prekey by generating the ephemeral
   DH key pair:
   * secret key `b` (80 bytes).
   * public key `B`.

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x55.

Prekey owner's instance tag (INT)
  The instance tag of the client that created the prekey.

Prekey owner's User Profile (USER-PROF)
  As described in the section [Creating a User Profile](#creating-a-user-profile).

Y Prekey owner's ECDH public key (POINT)
  First one-time use prekey value.

B Prekey owner's DH public key (MPI)
  Second one-time use prekey value. The ephemeral public DH
  key. Note that even though this is in uppercase, this is NOT a POINT.

```

### Validating a Prekey Message

To validate a prekey message:
* [Validate the user profile](#validating-a-user-profile)
* Check that the ECDH public key `Y` is on curve Ed448.
* Verify that the DH public key `B` is from the correct group and that it
  does not degenerate.

### Non-interactive Auth Message

This message terminates the non-interactive AKE and also contains an encrypted data message.

A valid non-interactive Auth message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile).
2. Generate an ephemeral ECDH key pair:
  * secret key `x` (57 bytes).
  * public key `X`.
3. Generate an ephemeral DH key pair:
  * secret key `a` (80 bytes).
  * public key `A`.
4. [Validate the prekey message](#validating-a-prekey-message).
5. At this point, the DAKE is complete for Bob:
	* Sets ratchet id `i` as 0.
	* Sets `j` as 0 TODO: (which means she will ratchet again)????
	* Calculates ECDH shared secret `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.
	* Calculates DH shared secret `k_dh = DH(our_dh.secret, their_dh)` and `mix_key`.
	* Extract the Public Shared Prekey from the user profile and set it as `their_shared_prekey`.
	* Calculates `κ = KDF_2(K_ecdh || ECDH(x, their_shared_prekey) || ECDH(x, Pkb) || k_dh)`.
	* Computes the Auth MAC key `Mk = KDF_2(0x01 || κ)`.
	* Computes the Mixed shared secret `K = KDF_2(0x02 || κ)`.
	* Calculates the SSID from shared secret: it is the first 8 bytes of `KDF_2(0x00 || K)`.
   * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = derive_ratchet_keys(K)`.
   * [Decides which chain key he will use](#deciding-between-chain-keys).
6. Compute `t = SHA3-512(Bobs_User_Profile) || SHA3-512(Alices_User_Profile) || Y || X || B || A || SHA3-512(Φ) || their_shared_prekey`.
7. Compute `sigma = Auth(Pka, ska, {Pkb, Pka, Y}, t)`. While computing `sigma`, keep the first 192 bits
   of the generated `c` value to be used as a nonce in the next step.
8. Follow the section ["When you send a Data Message"](when-you-send-a-data-message) to generate an
   encrypted message, using the nonce set in the previous step.
9. Compute `Auth MAC = SHA3-256(Mk || t || encrypted_data_message)`.

To verify a non-interactive Auth message:

1. Validate the user profile, and extract `Pka` from it.
2. Verifies that both ECDH and DH one-time use prekeys remain unused.
3. Compute `t = SHA3-512(Bobs_User_Profile) || SHA3-512(Alices_User_Profile) || Y || X || B || A || SHA3-512(Φ) || our_shared_prekey.public`.
4. Verify the `sigma` with [SNIZKPK Authentication](#snizkpk-authentication),
   as in check `sigma == Verify({Pkb, Pka, Y}, t)`.
5. Continue the DAKE for Alice:
	* Calculates ECDH shared secret `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.
	* Calculates DH shared secret `k_dh = DH(our_dh.secret, their_dh)` and `mix_key`.
	* Calculates `κ = KDF_2(K_ecdh || ECDH(our_shared_prekey.secret, their_ecdh) || ECDH(Ska, X) || k_dh)`.
	* Computes the Auth MAC key `Mk = KDF_2(0x01 || κ)`.
	* Computes the Mixed shared secret `K = KDF_2(0x02 || κ)`.
	* Calculates the SSID from shared secret: it is the first 8 bytes of `KDF_2(0x00 || K)`.
   * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = derive_ratchet_keys(K)`.
   * [Decides which chain key he will use](#deciding-between-chain-keys).
6. Verify the Auth Mac:
   * Extract the encrypted data message.
   * Compute `tag = SHA3-256(MK, || t || encrypted_data_message)`.
   * Extract the Auth MAC from the message and verify that `tag` is equal to the Auth MAC. If it is not,
     ignore the non-interactive auth message.
7. Set the message ID `j = 1` and compute the receiving chain key and calculate the encryption key:
   ```
   compute_chain_key(chain_r, ratchet_id, j)
   MKenc, MKmac = derive_enc_mac_keys(chain_r[ratchet_id][message_id])
   ```
8. Discard the `MKmac` key because it is not necessary for the first message delivered through a
   non-interactive auth message.
9. Setup the rest of the double ratchet key management system:
    * Set `their_ecdh` as the "Sender's Public ECDH key" from the message.
    * Set `their_dh` as the "Sender's Public DH Key" from the message, if it
      is not NULL.
    * Add the Auth MAC key to list `mac_keys_to_reveal`.

A non-interactive Auth is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.

Message type (BYTE)
  The message has type 0x04.

Sender Instance tag (INT)
  The instance tag of the person sending this message.

Receiver Instance tag (INT)
  The instance tag of the intended recipient.

Y Receiver's ECDH public key (POINT)
  First part of the one-time use prekey value.

B Receiver's DH public key (MPI)
  Second part of the one-time use prekey value. The ephemeral public DH
  key. Note that even though this is in uppercase, this is NOT a POINT.

Sender's User Profile (USER-PROF)
  As described in the section 'Creating a User Profile'.

X (POINT)
  The ephemeral public ECDH key.

A (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase,
  this is NOT a POINT.

Auth MAC (MAC)
  The SHA3 MAC with the appropriate MAC key (see above) for the message of the SNIZKPK.

Sigma (SNIZKPK)
  The SNIZKPK Auth value.

Encrypted message (DATA)
  Using the appropriate encryption key (see below) derived from the
  sender's and recipient's DH public keys (with the keyids given in this
  message), perform XSalsa20 encryption of the message. The nonce used for
  this operation is also included in the header of the data message
  packet.

```

### Publishing prekeys

An OTRv4 client must generate a user's prekey messages and publish them to a
prekey server. Implementers are expected to create their own policy dictating
how often their clients upload prekey messages to the prekey server. Prekey
messages expire when their user profile expires. Thus new prekey messages
should be published to the prekey server before they expire to keep valid
prekey messages available. In addition, one prekey message should be published
for every long term key that belongs to a user. This means that if Bob uploads
three long term keys for OTRv4 to his client, Bob's client must publish 3
prekey messages.

Details on how to interact with a prekey server to publish messages are outside
the scope of this protocol.

### Receiving prekeys

Details on how prekey messages may be received from a prekey server are outside
the scope of this protocol. This specification assumes that none, one, or more
than one prekey messages may arrive. If the prekey server cannot return any
prekey messages, the non-interactive DAKE must wait until one can be obtained.

The following guide is meant to help implementers identify and remove invalid
prekey messages and invalid situations.

Use the following checks to validate a prekey message. If any of them fail,
ignore the message:
  * Check if the user profile is not expired
  * Check if the OTR version of the prekey message matches one of the versions
  * signed in the user profile contained in the prekey message
  * Check if the user profile version is supported by the receiver

If one prekey message is received:
  * If the prekey message is valid, decide whether to send a non-interactive
    auth message based on whether the long term key in the use profile is
    trusted or not.

If many prekey messages are received:
  * Remove all invalid prekey messages.
  * Remove all duplicate prekey messages in the list.
  * If multiple valid messages remain, check for invalid situations:
      * If multiple prekey messages exist with the same instance tag, the same version,
        and the same long term keys in the user profile, then one of the messages is
        invalid. The safest thing to do is to remove all prekey messages associated
        with this situation.
  * If one prekey message remains:
      * Decide whether to send a message using this prekey message based on whether the
        long term key within the use profile is trusted or not.
  * If multiple valid prekey messages remain:
      * If there are keys that are untrusted and trusted in the list of
        messages, decide whether to only use messages that contain trusted long
        term keys.
      * If there are several instance tags in the list of prekey messages, decide
        whether to send one message per instance tag or to send a message
        only to one instance tag.
          * If there are multiple prekey messages per instance tag, decide whether to
            send multiple messages to the same instance tag.

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange [data messages](#data-message). The Double Ratchet is
initialized with the shared secret established in the DAKE. Detailed validation
and processing of each data message is described in the [section on receiving
encrypted data messages](#receiving-an-encrypted-data-message).

A message with an empty human-readable part (the plaintext is of zero length, or
starts with a NULL) is a "heartbeat" message. This message is useful for key
rotations and revealing MAC keys. It should not be displayed to the user.

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
  * Calculate the `K = KDF_2(K_ecdh || mix_key)`.
  * Derive new set of keys `root[i], chain_s[i][0], chain_r[i][0] = derive_ratchet_keys(K)`.
  * Securely delete the root key and all chain keys from the ratchet `i-2`.
  * Securely delete `K`.
  * Forget and reveal MAC keys. The conditions for revealing MAC keys is
    stated in the [Revealing MAC keys](#revealing-mac-keys) section.

Otherwise:

  * Increment current sending message ID `j = j+1`.
  * Derive the next sending chain key `derive_chain_key(chain_s, i, j)`.
  * Securely delete `chain_s[i][j-1]`.

In both cases:

  * Calculate the encryption key (`MKenc`) and the MAC key (`MKmac`):

   ```
   MKenc, MKmac = derive_enc_mac_keys(chain_s[i][j])
   ```

  * When creating a non-interactive auth message, construct a `nonce` from the
    first 24 bytes of the `c` variable created when constructing `sigma`. When
    creating a regular data message, generate a new random 24 bytes value to be
    the `nonce`.
  * Use the encryption key to encrypt the message:

   ```
   Encrypted_message = XSalsa20_Enc(MKenc, nonce, m)
   ```

  * When creating a non-interactive auth message, do not create a MAC tag. This is
    not necessary since the MAC tag created with the non-interactive DAKE includes
    the data message. When creating a regular data message, use the MAC key to create
    a MAC tag. MAC all the sections of the data message from the protocol version to
    the encrypted message.

   ```
   Authenticator = KDF_2(MKmac || Data_message_sections)
   ```

#### When you receive a Data Message:

* Use the `message_id` to compute the receiving chain key, and calculate
encryption and MAC keys.

  ```
    compute_chain_key(chain_r, ratchet_id, message_id)
    MKenc, MKmac = derive_enc_mac_keys(chain_r[ratchet_id][message_id])
  ```

* Use the MAC key (`MKmac`) to verify the MAC of the message. If the message
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

### Extra symmetric key

OTRv3 defines an additional symmetric key that can be derived by the
communicating parties for use of application-specific purposes, such as file
transfer, voice encryption, etc. When one party wishes to use the extra
symmetric key, they create a type `8 TLV` attached to a Data Message. The key
itself is then derived from `K`. The extra symmetric key is derived by
calculating `KDF_2(0xFF || K)`.

Upon receipt of the Data Message containing the type 8 TLV, the recipient will
compute the extra symmetric key in the same way. Note that the value of the
extra symmetric key is not contained in the TLV itself.

### Revealing MAC Keys

We reveal old MAC keys to provide [forgeability of messages](#forging-transcripts).
Old MAC keys are keys from already received messages and, therefore, will no
longer be used to verify the authenticity of the message.

The first data message sent every ratchet reveals MAC keys.

Old MAC keys are formatted as a list of concatenated 64 byte values.

A MAC key is added to `mac_keys_to_reveal` after a participant has verified
a message associated with the MAC key.

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

  This state is entered after DAKE is finished. This will happen after Auth-I
  message is sent, received and validated. Messages sent in this state are encrypted.

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
  message should be discarded and the user optionally warned. Nevertheless,
  the Identity Message may not specify the receiver's instance tag. In
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
the AKE according to one compatible version he supports.

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
  * Reply with an Auth-R message.
  * Transition to the `WAITING_AUTH_R` state.

If the state is `WAITING_AUTH_R`:

This indicates that both you and the other participant have sent Identity
messages to each other. This can happen if they send you an Identity message
before receiving yours.

To agree on an Identity message to use for this conversation:

  * Validate the Identity message and ignore the message if it fails.
  * Compare the `X` (as a 57-byte unsigned little-endian value) you sent in your
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

  * If the instance tag in the message is not the instance tag you are currently
    talking to, ignore the message.
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

  * If the instance tag in the message is not the instance tag you are currently
    talking to, ignore the message.
  * Validate the Auth-R message and ignore the message if it fails.
  * Transition state to `ENCRYPTED_MESSAGES`.
  * Initialize the double ratcheting.

If the state is not `WAITING_AUTH_I`:

  * Ignore this message.

#### Sending an encrypted message to an offline participant

1. Send a non-interactive auth message.
2. Transition to `ENCRYPTED_MESSAGES` state.

#### Receiving a non-interactive auth message

If the state is `FINISHED`:
    * Ignore the non-interactive auth message.

Else:

    * Receive the non-interactive auth message.
    * Transition to `ENCRYPTED_MESSAGES` state.

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
      * If the instance tag in the message is not the instance tag you are currently
        talking to, ignore the message.
      * Verify that the public ECDH key is on curve Ed448.
      * Verify that the public DH key is from the correct group and that it does not degenerate.

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

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

If the version is 4:
  If a TLV type 1 is received in the `START` state, stay in that state, else
  transition to the START state and [reset the state variables and key
  variables](#resetting-state-variables-and-key-variables). Resetting state
  variables and key variables

If the version is 3:
  * Transition to 'MSGSTATE_FINISHED'.
  * Inform the user that its correspondent has closed its end of the private connection.

## Socialist Millionaires Protocol (SMP)

SMP in OTRv4 shares the same TLVs and flow as SMP in OTRv3 with the following
exceptions. Please refer to the version 3 spec for details on how it handles
SMP [\[2\]](#references).

In OTRv3, SMP Message 1 is used when the user does not specify an SMP question.
If a question is supplied, SMP Message 1Q is used. OTRv4 is simplified to use
only SMP Message 1 for both cases. When a question is not present, the user
specified question section has length `0` and value `NULL`.

OTRv4 creates fingerprints using SHA3-512, which increases their size from
OTRv3. Thus, the size of the fingerprint in the "Secret Information" section of
OTRv3 [\[7\]](#references) should be 64 bytes.

Lastly, OTRv4 uses Ed448 as the cryptographic primitive. This changes the way
values are serialized and how they are computed. To define the SMP values
under Ed448, we reuse the previously defined generator `G` for Ed448:

```
G = (11781216126343694673728248434331006466518053535701637341687908214793940427
7809514858788439644911793978499419995990477371552926308078495, 19)
```

The computations below use the SMP secret value explained
[here](#secret-information).

### SMP Overview

Assuming that Alice begins the exchange:

**Alice:**

* Picks random values `a2` and `a3` in `Z_q`.
* Picks random values `r2` and `r3` in `Z_q`.
* Computes `c2 = HashToScalar(1 || G * r2)` and `d2 = r2 - a2 * c2`.
* Computes `c3 = HashToScalar(2 || G * r3)` and `d3 = r3 - a3 * c3`.
* Sends Bob a SMP message 1 with `G2a = G * a2`, `c2`, `d2`, `G3a = G * a3`,
  `c3` and `d3`.

**Bob:**

* Validates that `G2a` and `G3a` are on the curve Ed448, that they are in
  the correct group, and that they do not degenerate.
* Picks random values `b2` and `b3` in `Z_q`.
* Picks random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`.
* Computes `G2b = G * b2` and `G3b = G * b3`.
* Computes `c2 = HashToScalar(3 || G * r2)` and `d2 = r2 - b2 * c2`.
* Computes `c3 = HashToScalar(4 || G * r3)` and `d3 = r3 - b3 * c3`.
* Computes `G2 = G2a * b2` and `G3 = G3a * b3`.
* Computes `Pb = G3 * r4` and `Qb = G * r4 + G2 * HashToScalar(y)`, where y is
  the SMP secret value.
* Computes `cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6)`,
  `d5 = r5 - r4 * cp` and `d6 = r6 - HashToScalar(y) * cp`.
* Sends Alice a SMP message 2 with `G2b`, `c2`, `d2`, `G3b`, `c3`, `d3`, `Pb`,
  `Qb`, `cp`, `d5` and `d6`.

**Alice:**

* Validates that `G2b` and `G3b` are on the curve Ed448, that they are in
  the correct group and that they do not degenerate.
* Computes `G2 = G2b * a2` and `G3 = G3b * a3`.
* Picks random values `r4`, `r5`, `r6` and `r7` in `Z_q`.
* Computes `Pa = G3 * r4` and `Qa = G * r4 + G2 * HashToScalar(x)`, where x is
  the SMP secret value.
* Computes `cp = HashToScalar(6 || G3 * r5 || G * r5 + G2 * r6)`,
  `d5 = r5 - r4 * cp` and `d6 = r6 - HashToScalar(x) * cp`.
* Computes `Ra = (Qa - Qb) * a3`.
* Computes `cr = HashToScalar(7 || G * r7 || (Qa - Qb) * r7)` and
  `d7 = r7 - a3 * cr`.
* Sends Bob a SMP message 3 with `Pa`, `Qa`, `cp`, `d5`, `d6`, `Ra`, `cr` and
  `d7`.

**Bob:**

* Validates that `Pa`, `Qa`, and `Ra` are on the curve Ed448 that they are in
  the correct group and that they do not degenerate.
* Picks a random value `r7` in `Z_q`.
* Computes `Rb = (Qa - Qb) * b3`.
* Computes `Rab = Ra * b3`.
* Computes `cr = HashToScalar(8 || G * r7 || (Qa - Qb) * r7)` and
  `d7 = r7 - b3 * cr`.
* Checks whether `Rab == Pa - Pb`.
* Sends Alice a SMP message 4 with `Rb`, `cr`, `d7`.

**Alice:**

* Validates that `Rb` is on curve Ed448, that it is in the correct group, and
  that it does not degenerate.
* Computes `Rab = Rb * a3`.
* Checks whether `Rab == Pa - Pb`.

If everything is done correctly, then `Rab` should hold the value of `(Pa - Pb)
* ((G2 * a3 * b3) * (x - y))`. This test will only succeed if the secret
information provided by each participant are equal (essentially `x == y`).
Further, since `G2 * a3 * b3` is a random number not known to any party, if `x`
is not equal to `y`, no other information is revealed.

### Secret information

The secret information `x` and `y` compared during this protocol contains not
only information entered by the users, but also information unique to the
conversation in which SMP takes place. This includes the Secure Session ID
(SSID) whose creation is described [here](#non-interactive-auth-message).

Specifically, the format is:

```
Version (BYTE)
  The version of SMP used. The version described here is 1.
Initiator fingerprint (64 BYTE)
  The fingerprint that the party initiating SMP is using in the current
  conversation.
Responder fingerprint (64 BYTE)
  The fingerprint that the party that did not initiate SMP is using in the
  current conversation.
Secure Session ID or SSID
User-specified secret
  The input string given by the user at runtime.
```

The SHA3-512 hash of the above is taken, and the digest becomes the SMP secret
value (`x` or `y`) to be used in SMP. The additional fields ensure that not
only do both parties know the same secret input string, but no man-in-the-
middle is capable of reading their communication either.

### SMP Hash function

There are many places where a SHA3-512 hash is taken of an integer followed by
other values. This is defined as `HashToScalar(i || v)` where `i` is an integer
used to distinguish the calls to the hash function and `v` is some value.
Hashing is done in this way to prevent Alice from replaying Bob's zero
knowledge proofs or vice versa.

### SMP message 1

Alice sends SMP message 1 to begin a ECDH exchange to determine two new
generators, `g2` and `g3`. A valid SMP message 1 is generated as follows:

1. Determine her secret input `x`, which is to be compared to Bob's secret
   `y`, as specified in the [Secret Information section](#secret-information).
2. Pick random values `a2` and `a3` in `Z_q`. These will be Alice's
   exponents for the ECDH exchange to pick generators.
3. Pick random values `r2` and `r3` in `Z_q`. These will be used to
   generate zero-knowledge proofs that this message was created according
   to the SMP protocol.
4. Compute `G2a = G * a2` and `G3a = G * a3`.
5. Generate a zero-knowledge proof that the value `a2` is known by setting
   `c2 = HashToScalar(1 || G * r2)` and `d2 = r2 - a2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value `a3` is known by setting
   `c3 = HashToScalar(2 || G * r3)` and `d3 = r3 - a3 * c3 mod q`.
7. Store the values of `x`, `a2` and `a3` for use later in the protocol.


The SMP message 1 has the following data and format:

```
Question (DATA)
  A user-specified question, which is associated with the user-specified secret
  information. If there is no question input from the user, the length of this is
  0 and the data is NULL.

G2a (POINT)
  Alice's half of the ECDH exchange to determine G2.

c2 (SCALAR), d2 (SCALAR)
  A zero-knowledge proof that Alice knows the value associated with her
  transmitted value G2a.

G3a (POINT)
  Alice's half of the ECDH exchange to determine G3.

c3 (SCALAR), d3 (SCALAR)
  A zero-knowledge proof that Alice knows the value associated with her
  transmitted value G3a.

```

### SMP message 2

SMP message 2 is sent by Bob to complete the DH exchange to determine the new
generators, `g2` and `g3`. It also begins the construction of the values used in
the final comparison of the protocol. A valid SMP message 2 is generated as
follows:

1. Validate that `G2a` and `G3a` are on curve Ed448, that they are in the
   correct group, and that they do not degenerate.
2. Determine Bob's secret input `y`, which is to be compared to Alice's secret
   `x`.
3. Pick random values `b2` and `b3` in `Z_q`. These will be used for creating
   the generators `g2` and `g3`.
4. Pick random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`. These
   will be used to add a blinding factor to the final results, and to generate
   zero-knowledge proofs that this message was created honestly.
5. Compute `G2b = G * b2` and `G3b = G * b3`.
6. Generate a zero-knowledge proof that the value `b2` is known by setting
   `c2 = HashToScalar(3 || G * r2)` and `d2 = r2 - b2 * c2 mod q`.
7. Generate a zero-knowledge proof that the value `b3` is known by setting
   `c3 = HashToScalar(4 || G * r3)` and `d3 = r3 - b3 * c3 mod q`.
8. Compute `G2 = G2a * b2` and `G3 = G3a * b3`.
9. Compute `Pb = G3 * r4` and `Qb = G * r4 + G2 * HashToScalar(y)`.
10. Generate a zero-knowledge proof that `Pb` and `Qb` were created according
   to the protocol by setting
   `cp = HashToScalar(5 || G3 * r5 || G * r5 + G2 * r6)`,
   `d5 = r5 - r4 * cp mod q` and `d6 = r6 - HashToScalar(y) * cp mod q`.
11. Store the values of `G3a`, `G2`, `G3`, `b3`, `Pb` and `Qb` for use later
    in the protocol.

The SMP message 2 has the following data and format:

```
G2b (POINT)
  Bob's half of the DH exchange to determine G2.

c2 (SCALAR), d2 (SCALAR)
  A zero-knowledge proof that Bob knows the exponent associated with his
  transmitted value G2b.

G3b (POINT)
  Bob's half of the ECDH exchange to determine G3.

c3 (SCALAR), d3 (SCALAR)
  A zero-knowledge proof that Bob knows the exponent associated with his
  transmitted value G3b.

Pb (POINT), Qb (POINT)
  These values are used in the final comparison to determine if Alice and Bob
  share the same secret.

cp (SCALAR), d5 (SCALAR), d6 (SCALAR)
  A zero-knowledge proof that Pb and Qb were created according to the protocol
  given above.
```

### SMP message 3

SMP message 3 is Alice's final message in the SMP exchange. It has the last of
the information required by Bob to determine if `x = y`. A valid SMP message 3
is generated as follows:

1. Validate that `G2b`, `G3b`, `Pb`, and `Qb` are on curve Ed448, that they
   are in the correct group, and that they do not degenerate.
2. Pick random values `r4`, `r5`, `r6` and `r7` in `Z_q`. These will
   be used to add a blinding factor to the final results and to generate
   zero-knowledge proofs that this message was created honestly.
3. Compute `G2 = G2b * a2` and `G3 = G3b * a3`.
4. Compute `Pa = G3 * r4` and `Qa = G * r4 + G2 * HashToScalar(x)`.
5. Generate a zero-knowledge proof that `Pa` and `Qa` were created according to
   the protocol by setting
   `cp = HashToScalar(6 || G3 * r5 || G * r5 + G2 * r6)`,
   `d5 = r5 - r4 * cp mod q` and `d6 = r6 - HashToScalar(x) * cp mod q`.
6. Compute `Ra = (Qa - Qb) * a3`.
7. Generate a zero-knowledge proof that `Ra` was created according to the
   protocol by setting `cr = HashToScalar(7 || G * r7 || (Qa - Qb) * r7)` and
   `d7 = r7 - a3 * cr mod q`.
8. Store the values of `G3b`, `Pa - Pb`, `Qa - Qb` and `Ra` for use later in
   the protocol.

The SMP message 3 has the following data and format:

```
Pa (POINT), Qa (POINT)
  These values are used in the final comparison to determine if Alice and Bob
  share the same secret.

cp (SCALAR), d5 (SCALAR), d6 (SCALAR)
  A zero-knowledge proof that Pa and Qa were created according to the protocol
  given above.

Ra (POINT)
  This value is used in the final comparison to determine if Alice and Bob
  share the same secret.

cr (SCALAR), d7 (SCALAR)
  A zero-knowledge proof that Ra was created according to the protocol given
  above.
```

### SMP message 4

SMP message 4 is Bob's final message in the SMP exchange. It has the last of
the information required by Alice to determine if `x = y`. A valid SMP message
4 is generated as follows:

1. Validate that `Pa`, `Qa`, and `Ra` are on curve Ed448, that they are from the
   correct group, and that they do not degenerate.
2. Pick a random value `r7` in `Z_q`. This will be used to generate
   Bob's final zero-knowledge proof that this message was created honestly.
3. Compute `Rb = (Qa - Qb) * b3`.
4. Generate a zero-knowledge proof that `Rb` was created according to the
   protocol by setting
   `cr = HashToScalar(8 || G * r7 || (Qa - Qb) * r7)` and `d7 = r7 - b3 * cr mod q`.

The SMP message 4 has the following data and format:

```
Rb (POINT)
  This value is used in the final comparison to determine if Alice and Bob
  share the same secret.

cr (SCALAR), d7 (SCALAR)
  A zero-knowledge proof that Rb was created according to this SMP protocol.
```

### The SMP state machine

OTRv4 does not change the state machine for SMP from OTRv3. But the following
sections detail how values are computed differently during some states.

#### Receiving a SMP message 1

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

If smpstate is not `SMPSTATE_EXPECT1`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Alice.

If smpstate is `SMPSTATE_EXPECT1`:

* Verify Alice's zero-knowledge proofs for G2a and G3a:
  1. Check that both `G2a` and `G3a` are on curve Ed448, that they are part of the
     same group, and that they do not degenerate.
  2. Check that `c2 = HashToScalar(1 || G * d2 + G2a * c2)`.
  3. Check that `c3 = HashToScalar(2 || G * d3 + G3a * c3)`.
* Create a SMP message 2 and send it to Alice.
* Set smpstate to `SMPSTATE_EXPECT3`.

#### Receiving a SMP message 2

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

If smpstate is not `SMPSTATE_EXPECT2`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT2`:

* Verify Bob's zero-knowledge proofs for `G2b`, `G3b`, `Pb` and `Qb`:
  1. Check that `G2b`, `G3b`, `Pb` and `Qb` are on curve Ed448 and that they
     do not degenerate.
  2. Check that `c2 = HashToScalar(3 || G * d2 + G2b * c2)`.
  3. Check that `c3 = HashToScalar(4 || G * d3 + G3b * c3)`.
  4. Check that `cp = HashToScalar(5 || G3 * d5 + Pb * cp || G * d5 + G2 * d6 +
     Qb * cp)`.
* Create SMP message 3 and send it to Bob.
* Set smpstate to `SMPSTATE_EXPECT4`.

#### Receiving a SMP message 3

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

If smpstate is not `SMPSTATE_EXPECT3`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT3`:

* Verify Alice's zero-knowledge proofs for `Pa`, `Qa` and `Ra`:
  1. Check that `Pa`, `Qa` and `Ra` are on curve Ed448 and that they do not
     degenerate.
  2. Check that `cp = HashToScalar(6 || G3 * d5 + Pa * cp || G * d5 + G2 * d6 +
     Qa * cp)`.
  3. Check that `cr = HashToScalar(7 || G * d7 + G3a * cr || (Qa - Qb) * d7 +
     Ra * cr)`.
* Create a SMP message 4 and send it to Alice.
* Check whether the protocol was successful:
  1. Compute `Rab = Ra * b3`.
  2. Determine if `x = y` by checking the equivalent condition that
     `Pa - Pb = Rab`.
* Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from
  Alice.

#### Receiving a SMP message 4

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

If smpstate is not `SMPSTATE_EXPECT4`:

Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is SMPSTATE_EXPECT4:

* Verify Bob's zero-knowledge proof for Rb:
   1. Check that `Rb` is on curve Ed448 and that it does not degenerate.
   2. Check that `cr = HashToScalar(8 || G * d7 + G3 * cr || (Qa - Qb) * d7 + Rb * cr)`.
* Check whether the protocol was successful:
    1. `Compute Rab = Rb * a3`.
    2. Determine if `x = y` by checking the equivalent condition that
       `(Pa - Pb) = Rab`.
* Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected
  from Bob.

## Implementation Notes

### Considerations for networks that allow multiple devices

When using a transport network that allows multiple devices to be
simultaneously logged in with the same peer identifier, make sure to identify
the other participant by its device-specific identifier and not only the peer
identifier (for example, using XMPP full JID instead of bare JID). Doing so
allows establishing an OTR channel at the same time with multiple devices from
the other participant at the cost of managing exposure of this to the message
client (for example, XMPP clients can decide to reply only to the device you
have more recently received a message from).

## Forging Transcripts

OTRv4 expects each implementation of this specification to expose an interface
for producing forged transcripts. These forging operations must use the same
functions used for honest conversations. This section will outline which
operations must be exposed and include guidance to forge messages.

The major utilities are:

```
Parse
  Parses given OTR messages to the values of each of the fields in
  a message. This shows the values of all the fields.

Modify Data Message
  If an encrypted data message cannot be read because you don't
  know the message key (or a key used to derive this message key) but it can
  be guessed that the string `x` appears at a given place in the message,
  this method will replace the old text with some new desired text with
  the same length. The result is a valid OTR message containing the new text.
  For example, if the string "hi" is accurately guessed to be at the beginning
  of an encrypted message, it can be replaced with the string "yo". In that way,
  a valid data message can be created with the new text.

  To achieve this:
  - XOR the old text and the new text. Store this value.
  - XOR the stored value again with the original encrypted message starting at
    a given offset.
  - Recalculate the MAC tag with the revealed MAC key associated with this
    message. The new tag is attached to the data message, replacing the old
    value.
```

[Pseudocode](#modify-an-encrypted-data-message) for modifying data messages is
included in the [Appendices](#appendices).

```
Read and Forge Data Message
  Read and forge allows someone in possession of a chain key to decrypt OTR
  messages or modify them as forgeries. It takes three inputs: the chain key,
  the OTR message and a new plain text message (optional). If a new
  message is included, the original text is replaced with the new message and
  a new MAC tag is attached to the data message.

  To achive this:
  - Decrypt the data message with the corresponding message key derived from
    the given chain key.
  - If a new message is given, replace the message with that one, encrypt and
    mac it accordingly.

Forge AKE and Session Keys
  Any participant of an OTR conversation may forge an AKE with another
  participant as long as they have their profile. This function will take the
  user profile and the secret long term key of one participant, and the user
  profile of the other. It will return an AKE transcript between the two parties.
  The participant's private key is required since it is used to authenticate the
  key exchange, but the resulting transcript is created in such a way that a
  cryptographic expert cannot identify which profile owner authenticated the
  conversation.

Show MAC Key
  This function takes a chain key and a message key number and shows the MAC key
  associated with those two values. For example, if the message key number is 3,
  the chain key is ratcheted 3 times, and the third MAC key is derived and
  returned. 'Show MAC key' may be used with the ReMAC Message function below in
  the case where a chain key has been compromised by an attacker and the attacker
  wishes to forge messages.

ReMAC Message
  This will make a new OTR Data Message with a given MAC key and an original OTR
  message. The user's message in the OTR message is already encrypted. A new MAC
  tag will be generated and replaced for the message. An attacker may use this
  function to forge messages with a compromised MAC key.

Forge Entire Transcript
  The Forge Entire Transcript function will allow one participant to completely
  forge a transcript between them and another person in a way that its forgery
  cannot be cryptographically proven. The input will be: one participant's
  user profile, their secret key, another person's profile, and a list of plain
  text messages corresponding to what messages were exchanged. Each message in
  the list will have the structure: 1) sender 2) plain text message, so that the
  function may precisely create the desired transcript. The participant's
  private key is required since it is used to authenticate the key exchange, but
  the resulting transcript is created in such a way that a cryptographic expert
  cannot identify which profile owner authenticated the conversation.
```

## Appendices

### SNIZKPK Authentication

The Authentication scheme consists of two functions:

`sigma = Auth(A_1, a_1, {A_1, A_2, A_3}, m)`, an authentication function.

`Verify({A_1, A_2, A_3}, sigma, m)`, a verification function.

#### Domain parameters

We reuse the previously defined G generator in elliptic curve parameters:

```
G = (11781216126343694673728248434331006466518053535701637341687908214793940427
7809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf393
2d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)
```

#### Authentication: Auth(A1, a1, {A1, A2, A3}, m):

A1 is the public value associated with a1, that is, `A1 = G*a1`.
m is the message to authenticate.

`A1`, `A2`, and `A3` should be checked to verify they are on curve Ed448.

1. Pick random values `t1, c2, c3, r2, r3` in Z_q.
2. Compute `T1 = G * t1`.
3. Compute `T2 = G * r2 + A2 * c2`.
4. Compute `T3 = G * r3 + A3 * c3`.
5. Compute `c = HashToScalar(G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Compute `c1 = c - c2 - c3 (mod q)`.
7. Compute `r1 = t1 - c1 * a1 (mod q)`.
8. Send `sigma = (c1, r1, c2, r2, c3, r3)`.

#### Verification: Verify({A1, A2, A3}, sigma, m)

`A1`, `A2`, and `A3` should be checked to verify they are on curve Ed448.

1. Parse sigma to retrieve components `(c1, r1, c2, r2, c3, r3)`.
2. Compute `T1 = G * r1 + A1 * c1`
3. Compute `T2 = G * r2 + A2 * c2`
4. Compute `T3 = G * r3 + A3 * c3`
5. Compute `c = HashToScalar(G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Check if `c ≟ c1 + c2 + c3 (mod q)`.

### HashToScalar

This function is `hashToScalar(d)`: d is an array of bytes.

1. Compute `h = KDF_2(d)` as an unsigned value, big-endian.
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

The D-H Commit Message consists of the protocol version, the message type, the sender's instance
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

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

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

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

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

If the instance tag in the message is not the instance tag you are currently talking to,
ignore the message.

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

1. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf "N. Unger, I. Goldberg: Improved Strongly Deniable Authenticated Key Exchanges for Secure Messaging"
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
16. https://eprint.iacr.org/2012/309.pdf "Mike Hamburg: Fast and compact elliptic-curve cryptography"
17. https://tools.ietf.org/rfc/rfc8032.txt "S. Josefsson and I. Liusvaara: Edwards-Curve Digital Signature Algorithm (EdDSA)"; RFC 8032 (Informational); IETF; Jan 2017