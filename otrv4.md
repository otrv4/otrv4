# OTR version 4

OTRv4 is a new version of OTR that provides a Deniable Authenticated Key
Exchange and better forward secrecy through the use of double ratcheting. OTR
works on top of an existing messaging protocol, like XMPP.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)
2. [High Level Overview](#high-level-overview)
3. [Assumptions](#assumptions)
4. [Security Properties](#security-properties)
5. [Notation and parameters](#notation-and-parameters)
6. [Conversation Initialization](#conversation-initialization)
  1. [Requesting conversation with older OTR versions](#requesting-conversation-with-older-otr-versions)
  2. [User Profile](#user-profile)
  3. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
7. [Data exchange](#data-exchange)
  1. [Data Message](#data-message)
  2. [Revealing MAC Keys](#revealing-mac-keys)
  3. [Fragmentation](#fragmentation)
8. [The protocol state machine](#the-protocol-state-machine)
9. [Socialist Millionaires' Protocol (SMP)](#socialist-millionaires-protocol-smp)
10. [Implementation Notes](#implementation-notes)

[Appendices](#appendices)

  1. [ROM DRE](#rom-dre)
  2. [ROM Authentication](#rom-authentication)

## Main Changes over Version 3

- Security level raised to 224 bits and based on elliptic curve cryptography
  (ECC).
- Additional protection against transcript decryption in the case of ECC
  compromise.
- The cryptographic primitives and protocols have been updated:
  - Deniable Authenticated Key Exchange using Spawn ([2]).
  - Key management using the Double Ratchet Algorithm ([6]).
  - Upgraded SHA-1 and SHA-2 to SHA-3.
  - Switched from AES to XSalsa20.

## High Level Overview

```
Alice                                            Bob
--------------------------------------------------------------------------------
Requests OTR conversation           ------------->
Establishes Conversation with DAKE  <------------>  Establishes Conversation with DAKE
Exchanges Data Messages             <------------>  Exchanges Data Messages
```

An OTRv4 conversation is established when one participant requests a
conversation, advertising which versions they support. If the other participant
supports one of these versions, a deniable key exchange protocol is used to
establish a secure channel. Encrypted messages are then exchanged in this secure
channel with forward secrecy.

## Assumptions

Both participants are online at the start of a conversation.

Messages in a conversation can be exchanged over an insecure channel, where an
attacker can eavesdrop or interfere with the encrypted messages.

The network model provides in-order delivery of messages, but some messages
may not be delivered.

OTRv4 does not protect against an active attacker performing Denial of Service
attacks to reduce availability.

## Security Properties

In an OTRv4 conversation, both sides can verify the identity of the other
participant but cannot transfer this knowledge to a third party.

Once an OTRv4 channel has been created, all messages transmitted through this
channel are confidential and their integrity is protected.

If key material has been compromised, previous messages are protected. In this
case, future messages are protected in future ratchets only.

Both parties can deny that they have participated in a conversation. They can
also deny having sent any of the exchanged messages in the conversation. The
respective party can be certain of the authenticity of the messages but cannot
transfer this knowledge to someone else.

## Notation and parameters

This section contains information needed to understand the parameters,
variables and arithmetic used.

### Notation

Scalars and secret keys are in lower case, such as `x` or `y`. Points and
public keys are in upper case, such as `P` or `Q`.

Addition and subtraction of elliptic curve points `A` and `B` are `A + B` and
`A - B`. Addition of a point to another point generates a third point. Scalar
multiplication with a scalar `a` with an elliptic curve point `B` yields a
new point: `C = a * B`.

The concatenation of byte sequences `I` and `J` is `I || J`. In this case, `I`
and `J` represent a fixed-length byte sequence encoding the respective values.
See section [Data Types](#data-types) for encoding and decoding details.

### Elliptic Curve Parameters

OTRv4 uses the Ed448-Goldilocks ([4]) elliptic curve ([5]), which defines the
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

Number of bytes in p (|p|)
  56 bytes

Number of bytes in q (|q|)
  55 bytes

Non-square element in Z_p (d)
  -39081
```

A scalar modulo `q` is a "field element", and should be encoded and decoded
using the rules for MPIs.

### 3072 Diffie-Hellman Parameters

For the Diffie-Hellman group computations, the group is the one defined in RFC
3526 ([1]) with a 3072-bit modulus (hex, big-endian):

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
```

Note that this means that whenever you see an operation on a field element
from the above group, the operation should be done modulo the above prime.

## Data Types

OTRv4 uses almost the same data types as specified in OTRv3 (bytes, shorts,
ints, MPIs, and DATA) with the addition of:

```
Nonce (NONCE):
  24 bytes data

ED448 point (POINT):
  56 bytes data

User Profile (USER-PROF):
  Detailed in "User Profile Data Type" section
```

In order to serialize and deserialize the point, refer to Appendix A.1
(Encoding) and A.2 (Decoding) in Mike Hamburg's Decaf paper ([11]).

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
  nonce (NONCE)
  phi (DATA)
    Where (U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, phi) =
    DREnc(pubA, pubB, m)
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
Error: ERROR_CODE_1:". This code is used to identify which error is being
received for optional internationalization of the message.

Error Code List:

```
ERROR_CODE_1:
  Message cannot be decrypted
```

## Key management

In the DAKE, OTRv4 makes use of long-term Cramer-Shoup keys, ephemeral Elliptic
Curve Diffie-Hellman (ECDH) keys, and ephemeral Diffie-Hellman (DH) keys.

For exchanging data messages, OTRv4 makes use of both the DH Ratchet (with ECDH)
and the Symmetric Key Ratchet from the Double Ratchet algorithm ([6]). A
cryptographic ratchet is a one-way mechanism for deriving new cryptographic keys
from previous keys. New keys cannot be used to calculate the old keys.

OTRv4 adds new 3072-bit (384-byte) DH keys, called the Mix Key Pair, to the
Double Ratchet algorithm. These keys are used to protect transcripts of data
messages in a case where ECC is broken. During the DAKE, both parties agree upon
the first set of DH keys. Then, during every third DH Ratchet in the Double
Ratchet, a new key is agreed upon. Between each DH Mix Key Ratchet, both sides
will conduct a Symmetric Mix Key Ratchet.

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

The previously mentioned variables are affected by these events:

* When you send a DAKE message (starting a new DAKE).
* Upon completing the DAKE.
* When you send a Data Message.
* When you receive a Data Message.
* When you receive a TLV type 1 (Disconnect)

### Generating ECDH and DH Keys

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
  A SHA3-256 of the shared DH key SHA3-256(k_dh).

K_ecdh:
  The serialized ECDH shared secret computed from an ECDH exchange.
  This is serialized as a POINT.
```

### Deciding Between Chain Keys

Both sides will compare their public keys to choose a chain key for sending
and receiving:

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

### Calculating Double Ratchet Keys

```
calculate_ratchet_keys(K):
  R = SHA3-512(0x01 || K)
  Ca = SHA3-512(0x02 || K)
  Cb = SHA3-512(0x03 || K)
  return R, decide_between_chain_keys(Ca, Cb)
```

### Ratcheting ECDH keys and Mix Keys

The sender will rotate into a new ECDH ratchet and a new Mix Key ratchet
before it sends the first message after receiving any messages from the other
side (i.e. the first reply). The following data messages will advertise a new
ratchet id as `i + 1`.

  * Increment the current ratchet id (`i`) by 1.
  * Reset the next sent message id (`j`) to 0.

When you ratchet the ECDH keys:

  * Generate a new ECDH key pair and assign it to `our_ecdh = generateECDH()`.
  * Calculate `K_ecdh = ECDH(our_ecdh.secret, their_ecdh)`.
  * Securely delete `our_ecdh.secret`.

When you ratchet the mix keys:

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

### Calculating Encryption and MAC keys

When sending or receiving data messages, you must calculate the message keys:

```
derive_enc_mac_keys(chain_key):
  MKenc = SHA3-256(0x01 || chain_key)
  MKmac = SHA3-512(0x02 || chain_key)
  return MKenc, MKmac
```

## Conversation Initialization

OTRv4 will initialize through a Query message or a whitespace tag, as discussed
in OTRv3 ([3]). After this, the conversation is authenticated using a deniable
authenticated key exchange (DAKE).

### Requesting conversation with older OTR versions

Bob might respond to Alice's request or notification of willingness to start a
conversation using OTRv3. If this is the case and Alice supports version 3,
the protocol falls back to OTRv3 ([3]). If Alice does not support version 3,
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
published). Another client may use XMPP's publish-subscribe extension (XEP-0060)
for publishing profiles.

When the user profile expires, it should be updated. The expiration and renewal
policy determine the frequency of the user profile publication.

Both parties include the user profile in the DAKE. Participants in the DAKE do
not request the profile from the site of publication. Both the published profile
and the profile used in the DAKE should match each other.

#### Creating a User Profile

To create a user profile, assemble:

1. User's Cramer-Shoup long term public key.
2. Version: a string corresponding to the user's supported OTR versions.
   The format is described in OTRv3 under the section "OTR Query Messages"
   ([3]).
3. Profile Expiration: Expiration date in standard Unix 64-bit format
   (seconds since the midnight starting Jan 1, 1970, UTC, ignoring leap seconds)
4. Profile Signature: One of the Cramer-Shoup secret key values (`z`) and its
   generator (`G1`) is used to create signatures of the entire profile
   excluding the signature itself. The size of the signature is 112 bytes.
   It is created using the Ed448 signature algorithm as documented in ([4]).
5. Transition Signature (optional): A signature of the profile excluding
   Profile Signatures and itself signed by the user's OTRv3 DSA key. The
   transitional signature that enables contacts that trust user's version 3
   DSA key to trust the user's profile in version 4. This is only used if the
   user supports versions 3 and 4.

Then this profile must be published in a public place, like an untrusted
server.

#### Renewing a Profile

If a renewed profile is not published in a public place, and if the only
publicly available profile is expired, the user's participation deniability is
at risk.

Before the profile expires, the user must publish an updated profile with a
new expiration date. The client establishes the frequency of expiration - this
can be configurable. A recommended value is two weeks.

#### User Profile Data Type

```
User Profile (USER-PROF):
  Cramer-Shoup public key (CRAMER-SHOUP-PUBKEY)
  Version (BYTE)
  Profile Expiration (PROF-EXP)
  Profile Signature (MPI)
  (optional) Transitional Signature (MPI)

Profile Expiration (PROF-EXP):
  8 bytes signed value, big-endian
```

### Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the Deniable Authenticated Key Exchange.
This is a way to mutually agree upon shared keys for the two parties and
authenticate one another while providing participation deniability.

This protocol is derived from the Spawn protocol ([2]), which uses dual-receiver
encryption (DRE) and a non-interactive zero-knowledge proof of knowledge
(NIZKPK) for authentication (Auth).

Alice's long-term Cramer-Shoup key-pair is `ska = (x1a, x2a, y1a, y2a, za)` and
`PKa = (Ca, Da, Ha)`. Bob's long-term Cramer-Shoup key-pair is `skb = (x1b, x2b,
y1b, y2b, zb)` and `PKb = (Cb, Db, Hb)`. Both key pairs are generated by
`DRGen()`.

#### Overview

```
Alice                                    Bob
---------------------------------------------------
Query Message or Whitespace Tag ------->
                                <------- Prekey (psi_1)
               DRE-Auth (psi_2) ------->
                                         Verify & Decrypt (psi_2)
```

Bob will be initiating the DAKE with Alice.

**Bob:**

1. Generates and sets `our_ecdh` as ephemeral  ECDH keys.
2. Generates and sets `our_dh` as ephemeral 3072-DH keys.
3. Sends Alice a Pre-key message.

**Alice:**

1. Receives Pre-key message from Bob:
    * Validates Bob`s User Profile.
    * Sets `their_ecdh` as ECDH ephemeral public key.
    * Sets `their_dh` as DH ephemeral public key.
2. Generates and sets `our_ecdh` as ephemeral ECDH keys.
3. Generates and sets `our_dh` as ephemeral 3072-DH keys.
4. Sends Bob a DRE-Auth message (see DRE-Auth message section).
5. At this point, the DAKE is complete for Alice:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 0 (which means she will ratchet again).
    * Calculates ECDH shared secret `K_ecdh`.
    * Calculates DH shared secret `k_dh` and `mix_key`.
    * Calculates Mixed shared secret `K = SHA3-512(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: it is the first 8 bytes of `SHA3-256(0x00 || K)`.
    * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = calculate_ratchet_keys(K)`.

**Bob:**

1. Receives DRE-Auth message from Alice:
    * Validates Alice`s User Profile.
    * Verify the authentication `sigma`(see in ROM Authentication and DRE-Auth message section).
2. Decrypts `gamma` and verifies the following properties of the decrypted message. If any of
   the verifications fail, the message is ignored:
    * The message is of the correct form (e.g., the fields are of the expected
     length).
    * Bob's User Profile is the first one listed
    * Alice's User Profile is the second one listed, and it matches the
     one transmitted outside of the ciphertext
    * `(Y, B)` in the message is a prekey that Bob previously sent and has not been used.
3. Retrieve ephemeral public keys from Bob:
    * Sets `their_ecdh` as ECDH ephemeral public key.
    * Sets `their_dh` as DH ephemeral public key.
4. At this point, the DAKE is complete for Bob:
    * Sets ratchet id `i` as 0.
    * Sets `j` as 1.
    * Calculates ECDH shared secret `K_ecdh`.
    * Calculates DH shared secret `k_dh` and `mix_key`.
    * Calculates Mixed shared secret `K = SHA3-512(K_ecdh || mix_key)`.
    * Calculates the SSID from shared secret: it is the first 8 bytes of `SHA3-256(0x00 || K)`.
    * Calculates the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = calculate_ratchet_keys(K)`.

#### Pre-key message

This is the first message of the DAKE. Bob sends it to Alice to commit to a
choice of DH and ECDH key. A valid Pre-key message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile).
2. Generate an ephemeral ECDH key pair:
  * secret key `y`.
  * public key `Y`.
3. Generate an ephemeral DH key pair:
  * secret key `b` (80 bytes).
  * public key `B`.

A Pre-key is an OTR message encoded as:

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x0F.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For a Pre-key message, this will
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
of Bob's ECDH ephemeral key and DH ephemeral key. The ECDH ephemeral public
keys and DH ephemeral public keys are encrypted with DRE and authenticated
with a NIZKPK.

A valid DRE-Auth message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile)
2. Generate an ephemeral ECDH key pair:
  * secret key `x`.
  * public key `X`
3. Generate an ephemeral DH key pair:
  * secret key `a` (80 bytes).
  * public key `A`.
4. Generate `m = Prof_B || Prof_A || Y || X || B || A`
5. Compute `DREnc(PKb, PKa, m)` and serialize it as a DRE-M value in the
   variable `gamma`.
6. Compute `sigma = Auth(Ha, za, {Hb, Ha, Y}, Prof_B || Prof_A || Y || B || gamma)`.

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
X (POINT)
  The ephemeral public ECDH key.
A (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase,
  this is NOT a POINT.
gamma (DRE-M)
  The Dual-receiver encrypted value.
sigma (AUTH)
  The Auth value.
```

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange [data messages](#data-message) initialized with the
shared secret established in the DAKE.

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

  * Ratchet the ECDH keys, see "Ratcheting ECDH keys and Mix Keys" section.
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

We reveal old MAC keys to provide forgeability of messages. Old MAC keys are
keys for already received messages and, therefore, will no longer be
used to verify the authenticity of the message.

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
  `total`, and the pieces be `piece\[1\],piece\[2\],...,piece[total]`.
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

  This state is entered when a participant receives or sends a Pre-key
  message. Data Messages sent in this state are queued for delivery in the
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
  Commit and Pre-key messages may not specify the receiver's instance tag. In
  this case the value is set to zero.
* The protocol is initialized with the allowed versions (3 and/or 4).

#### User requests to start an OTR conversation

Send an OTR Query Message or a plaintext message with a whitespace tag to the
correspondent.

Query Messages are constructed according to the section "OTR Query Messages" of
OTRv3 ([3]). The byte identifier for OTR version 4 is "4".

Whitespace tags have the same structure as defined in "Tagged plaintext
messages" of OTRv3 ([3]), and a 8 bytes tag "\x20\x20\x09\x09\x20\x09\x20\x20"
is used to indicate a willingness to use OTR version 4.

#### Receiving plaintext without the whitespace tag

Display the message to the user.

If the state is `ENCRYPTED_MESSAGES`, `DAKE_IN_PROGRESS`, or `FINISHED`:

  * The user should be warned that the message received was unencrypted.

#### Receiving plaintext with the whitespace tag

Remove the whitespace tag and display the message to the user.

If the tag offers OTR version 4 and version 4 is allowed:

  * Send a Pre-key Message.
  * Transition the state to `DAKE_IN_PROGRESS`.

If the tag offers OTR version 3 and version 3 is allowed:

  * Send a version 3 D-H Commit Message.
  * Proceed with the protocol as specified in OTRv3 "Receiving plaintext with
    the whitespace tag" ([3]).

#### Receiving a Query Message

If the Query Message offers OTR version 4 and version 4 is allowed:

  * Send a Pre-key Message.
  * Transition the state to `DAKE_IN_PROGRESS`.

If the Query message offers OTR version 3 and version 3 is allowed:

  * Send a version 3 D-H Commit Message.
  * Proceed with the protocol as specified in OTRv3 "Receiving a Query Message"
    ([3]).

#### Receiving OTRv3 Specific Messages (AKE or Data message)

Proceed as specified in OTRv3. See "The protocol state machine" section ([3]).

#### Receiving a Pre-key message

If the message is version 4 and version 4 is not allowed:

  * Ignore this message.

If the state is `START`:

  * Validate the Pre-key message.
  * If validation fails, ignore the message.
  * If validation succeeds:
      * send a DRE-Auth message
      * transition to the `ENCRYPTED_MESSAGES` state.

If the state is `DAKE_IN_PROGRESS`:

This indicates that both you and the other participant have sent Pre-key
messages to each other. This can happen if they send you a Pre-key message
before receiving yours.

To agree on a Pre-key message to use for this conversation:

  * Compare the `X` (as a 56-byte unsigned big-endian value) you sent in you
    Pre-key with the value from the message you received.
  * If yours is the lower hash value:
    * Ignore the received Pre-key message.

  * Otherwise:
    * Forget your old `X` value that you sent earlier.
    * Validate the pre-key message.
    * If validation succeeds:
      * Send a DRE-Auth message.
      * Transition to the `ENCRYPTED_MESSAGES` state.

If the state is `ENCRYPTED_MESSAGES`:

  * Validate the Pre-key message.
  * If validation fails, ignore the message.
  * If validation succeeds:
    * send a DRE-Auth message
    * keep in the `ENCRYPTED_MESSAGES` state.

To validate the Pre-key message, you should:

  * Verify that the user profile signature is valid.
  * Verify that the user profile is not expired.
  * Verify that the point `Y` received is on curve 448.
  * Verify that the DH public key `B` is from the correct group.

#### Sending a DRE-Auth message

* Compute the ECDH shared secret `K_ecdh`.
* Compute the mix key `mix_key`.
* Transition the state to `ENCRYPTED_MESSAGES`.
* Initialize the double ratcheting.
* Send a DRE-Auth Message.

#### Receiving a DRE-Auth message

If the message is version 4 and version 4 is not allowed, ignore this message.

If the state is not `DAKE_IN_PROGRESS`:

  * Ignore this message.

If the state is `DAKE_IN_PROGRESS`:

  * Verify that the profile signature is valid.
  * Verify that the profile is not expired.
  * If the auth `sigma` is valid, decrypt the DRE message and verify:
    * that the point `X` received is on curve 448.
    * that the DH public key `A` is from the correct group.

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

#### Receiving a Data Message

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
      * If the received message contains a TLV type 1 (Disconnected) ([3])
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

Transition to the START state. If a TLV type 1 is received in the `START` state, stay in that state.

## Socialist Millionaires Protocol (SMP)

SMP in version 4 shares the same TLVs and flow as SMP in OTRv3 with the
following exceptions.

In OTRv3, SMP Message 1 is used when a user does not specify an SMP question
and, if not, a SMP Message 1Q is used. OTRv4 is simplified to use only SMP
Message 1 for both cases. When a question is not present, the user specified
question section has length 0 and value NULL.

OTRv4 creates fingerprints using SHA3-512, which increases their size. Thus,
the size of the fingerprint in the "Secret Information" section of OTRv3 ([3])
should be 64 bytes in size.

Lastly, OTRv4 uses Ed448 as the cryptographic primitive. This changes the way
values are serialized and how they are computed. To define the SMP values
under Ed448, we reuse the previously defined generator for Cramer-Shoup:

```
G1 = (11781216126343694673728248434331006466518053535701637341687908214793940427
7809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf3932
d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)
```

### Overview

Assuming that Alice begins the exchange:

**Alice:**

* Picks random values `a2` and `a3` in `Z_q`.
* Picks random values `r2` and `r3` in `Z_q`.
* Computes `c2 = HashToScalar(1 || G*r2)` and `d2 = r2 - a2 * c2`.
* Computes `c3 = HashToScalar(2 || G*r3)` and `d3 = r3 - a3 * c3`.
* Sends Bob a SMP message 1 with `G2a = G*a2`, `c2`, `d2`, `G3a = G*a3`, `c3`
  and `d3`.

**Bob:**

* Picks random values `b2` and `b3` in `Z_q`.
* Picks random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`.
* Computes `G2b = G*b2` and `G3b = G*b3`.
* Computes `c2 = HashToScalar(3 || G*r2)` and `d2 = r2 - b2 * c2`.
* Computes `c3 = HashToScalar(4 || G*r3)` and `d3 = r3 - b3 * c3`.
* Computes `G2 = G2a*b2` and `G3 = G3a*b3`.
* Computes `Pb = G3*r4` and `Qb = G*r4 + G2*y`, where y is the 'actual secret'.
* Computes `cp = HashToScalar(5 || G3*r5 || G*r5 + G2*r6)`, `d5 = r5 - r4 * cp`
  and `d6 = r6 - y * cp`.
* Sends Alice a SMP message 2 with `G2b`, `c2`, `d2`, `G3b`, `c3`, `d3`, `Pb`,
  `Qb`, `cp`, `d5` and `d6`.

**Alice:**

* Computes `G2 = G2b*a2` and `G3 = G3b*a3`.
* Picks random values `r4`, `r5`, `r6` and `r7` in `Z_q`.
* Computes `Pa = G3*r4` and `Qa = G1*r4 + G2*x`, where x is the 'actual secret'.
* Computes `cp = HashToScalar(6 || G3*r5 || G*r5 + G2*r6)`, `d5 = r5 - r4 * cp`
  and `d6 = r6 - x * cp`.
* Computes `Ra = (Qa - Qb)*a3`.
* Computes `cr = HashToScalar(7 || G*r7 || (Qa - Qb)*r7)` and `d7 = r7 - a3 * cr`.
* Sends Bob a SMP message 3 with `Pa`, `Qa`, `cp`, `d5`, `d6`, `Ra`, `cr` and `d7`.

**Bob:**

* Picks a random value `r7` in `Z_q`.
* Computes `Rb = (Qa - Qb)*b3`.
* Computes `Rab = Ra*b3`.
* Computes `cr = HashToScalar(8 || G*r7 || (Qa - Qb)*r7)` and `d7 = r7 - b3 * cr`.
* Checks whether `Rab == Pa - Pb`.
* Sends Alice a SMP message 4 with `Rb`, `cr`, `d7`.

**Alice:**

* Computes `Rab = Rb*a3`.
* Checks whether `Rab == Pa - Pb`.

If everything is done correctly, then `Rab` should hold the value of
`(Pa - Pb) * ((G2*a3*b3)*(x - y))`, which means that the test at the end of the
protocol will only succeed if `x == y`. Further, since `G2*a3*b3` is a random
number not known to any party, if `x` is not equal to `y`, no other information
is revealed.

### Secret information

The secret information x and y compared during this protocol contains not only
information entered by the users, but also information unique to the
conversation in which SMP takes place. Specifically, the format is:

```
Version (BYTE)
  The version of SMP used. The version described here is 2.
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

Then the SHA3-256 hash of the above is taken, and the digest becomes the actual secret (x or y) to be used in SMP. The additional fields insure that not only do both parties know the same secret input string, but no man-in-the-middle is capable of reading their communication either.

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

SMP message 1 is sent by Alice to begin a DH exchange to determine two new
generators, `g2` and `g3`. A valid  SMP message 1 is generated as follows:

1. Determine her secret input `x`, which is to be compared to Bob's secret
   `y`, as specified in the "Secret Information" section.
2. Pick random values `a2` and `a3` in `Z_q`. These will be Alice's
exponents for the DH exchange to pick generators.
3. Pick random values `r2` and `r3` in `Z_q`. These will be used to
generate zero-knowledge proofs that this message was created according to the
protocol.
4. Compute `G2a = G*a2` and `G3a = G*a3`.
5. Generate a zero-knowledge proof that the value `a2` is known by setting
`c2 = HashToScalar(1 || G*r2)` and `d2 = r2 - a2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value `a3` is known by setting
`c3 = HashToScalar(2 || G*r3)` and `d3 = r3 - a3 * c3 mod q`.
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

1. Determine Bob's secret input `y`, which is to be compared to Alice's secret
   `x`.
2. Pick random values `b2` and `b3` in `Z_q`. These will used during
   the DH exchange to pick generators.
3. Pick random values `r2`, `r3`, `r4`, `r5` and `r6` in `Z_q`. These
   will be used to add a blinding factor to the final results, and to generate
   zero-knowledge proofs that this message was created honestly.
4. Compute `G2b = G*b2` and `G3b = G*b3`.
5. Generate a zero-knowledge proof that the value `b2` is known by setting
`c2 = HashToScalar(3 || G*r2)` and `d2 = r2 - b2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value `b3` is known by setting
`c3 = HashToScalar(4 || G*r3)` and `d3 = r3 - b3 * c3 mod q`.
7. Compute `G2 = G2a*b2` and `G3 = G3a*b3`.
8. Compute `Pb = G3*r4` and `Qb = G*r4 + G2*y`.
9. Generate a zero-knowledge proof that `Pb` and `Qb` were created according
   to the protocol by setting `cp = HashToScalar(5 || G3*r5 || G*r5 + G2*r6)`,
   `d5 = r5 - r4 * cp mod q` and `d6 = r6 - y * cp mod q`.
10. Store the values of `G3a`, `G2`, `G3`, `b3`, `Pb` and `Qb` for use later
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

1. Pick random values `r4`, `r5`, `r6` and `r7` in `Z_q`. These will
   be used to add a blinding factor to the final results, and to generate
   zero-knowledge proofs that this message was created honestly.
2. Compute `G2 = G2b*a2` and `G3 = G3b*a3`.
3. Compute `Pa = G3*r4` and `Qa = G*r4 + G2*x`.
4. Generate a zero-knowledge proof that `Pa` and `Qa` were created according to
   the protocol by setting `cp = HashToScalar(6 || G3*r5 || G*r5 + G2*r6)`,
   `d5 = r5 - r4 * cp mod q` and `d6 = r6 - x * cp mod q`.
5. Compute `Ra = (Qa - Qb) * a3`.
6. Generate a zero-knowledge proof that `Ra` was created according to the
   protocol by setting `cr = HashToScalar(7 || G*r7 || (Qa - Qb)*r7)` and
   `d7 = r7 - a3 * cr mod q`.
7. Store the values of `G3b`, `Pa - Pb`, `Qa - Qb` and `Ra` for use later in
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

1. Pick a random value `r7` in `Z_q`. This will be used to generate
Bob's final zero-knowledge proof that this message was created honestly.
2. Compute `Rb = (Qa - Qb) * b3`.
3. Generate a zero-knowledge proof that `Rb` was created according to the protocol by setting
	`cr = HashToScalar(8 || G*r7 || (Qa - Qb)*r7)` and `d7 = r7 - b3 * cr mod q`.

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
    4. Check that `cp = HashToScalar(5 || G3*d5 + Pb*cp || G*d5 + G2*d6 + Qb*cp)`.
* Create SMP message 3 and send it to Bob.
* Set smpstate to `SMPSTATE_EXPECT4`.

#### Receiving a SMP message 3

If smpstate is not `SMPSTATE_EXPECT3`:

Set smpstate to `SMPSTATE_EXPECT1` and send a SMP abort to Bob.

If smpstate is `SMPSTATE_EXPECT3`:

* Verify Alice's zero-knowledge proofs for `Pa`, `Qa` and `Ra`:
  1. Check that `Pa`, `Qa` and `Ra` are points in the curve.
  2. Check that `cp = HashToScalar(6 || G3*d5 + Pa*cp || G*d5 + G2*d6 +
     Qa*cp)`.
  3. Check that `cr = HashToScalar(7 || G*d7 + G3a*cr || (Qa - Qb)*d7 +
     Ra*cr)`.
* Create a SMP message 4 and send it to Alice.
* Check whether the protocol was successful:
  1. Compute `Rab = Ra*b3`.
  2. Determine if `x = y` by checking the equivalent condition that
     `Pa - Pb = Rab`.
* Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from
  Alice.

#### Receiving a SMP message 4

If smpstate is not `SMPSTATE_EXPECT4`:
Set smpstate to `SMPSTATE_EXPECT1` and send a type 6 TLV (SMP abort) to Bob.

If smpstate is SMPSTATE_EXPECT4:

* Verify Bob's zero-knowledge proof for Rb:
   1. Check that `Rb` is `>= 2` and `<= modulus-2`.
   2. Check that `cr = HashToScalar(8 || G1*d7 G3*cr || (Qa / Qb)*d7 + Rb*cr)`.

* Check whether the protocol was successful:
    1. `Compute Rab = Rb*a3`.
    2. Determine if `x = y` by checking the equivalent condition that
       `(Pa / Pb) = Rab`.

Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected
from Bob.

## Implementation Notes

### Considerations for networks which allow multiple devices

When using a transport network that allows multiple devices to be simultaneously
logged in with the same peer identifier, make sure to identify the other
participant by its device-specific identifier and not only the peer identifier
(for example, using XMPP full JID instead of bare JID). Doing so allows
establishing an OTR channel at the same time with multiple devices from the
other participant at the cost of how to expose this to the message client (for
example, XMPP clients can decide to reply only to the device you have more
recently received a message from).

## Appendices

### ROM DRE

The DRE scheme consists of three functions:

`PK, sk = DRGen()`, a key generation function.

`gamma = DREnc(PK1, PK2, m)`, an encryption function.

`m = DRDec(PK1, PK2, ski, gamma)`, a decryption function.

#### Domain parameters

The Cramer-Shoup scheme uses a group (`G`, `q`, `G1`, `G2`). This is a group
with the same `q` as Curve 448. The generators `G1` and `G2` are:

```
G1 = (1178121612634369467372824843433100646651805353570163734168790821479394042
77809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf393
2d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)

G2 = (3913607664015387778525440871338748426958505468847952048812636074953060342
73165958212315431889921087320515545432683148400791008269241572,
5744090938718597086501900481389618127080777801589371288623121699156379421463562
87346163045114803481001237424605972373287716834704142326)

= (0x89d75bf8561f2e0a3e726ad8480ddb510c7dbd1129b9443694d2f59dd833b5b05a44baf77e
b7da584eb4a951bb3eb15b0b29c66a7fbf0ce4,
0xca500f343628b32f0059b76f9fdd5b3c5bf1b176e4681af329da6fba07f49e3e4323192c5f7e4
8cc8569615b50d9183ef9fd53e8f9a4aff6)
```

Generator 1 (`G1`) is the base point of Ed448. Generator 2 (`G2`) was created
with this code ([9]) that works as follows:

1. Select `x`, a "nothing up my sleeve" value (a value chosen above suspicion
   of hidden properties). In this case, we choose `OTRv4 g2`.
2. Set counter `c = 0` and increment it until a generator is found:

  * Concatenate `x` with `c` in a string format `ss`.
  * Compute `H = SHA3-512(ss)`
  * Compute `point = decodepoint(H)`:
    * Decode `y`. An element `(x, y)` is encoded as a 448-bit array,namely the
      (448 − 1)-bit encoding of `y` followed by a sign bit; the sign bit is 1
      iff `x` is negative.
    * Recover `x` through decoded `y` by `x = ± sqrt((1-y^2)/(1-dy^2))`:
      * Calculate `xx = (1-y^2) * inv(1-dy^2)`.
      * Compute candidate root `z = xx ^ (p+1)/4 (mod p)`.
      * If `xx == z^2`, then `z` is `x`:
        * Compute the point `P = (x,y)` and check if it is on the curve.
	* Compute `g = point^cofactor`.
	* If `g^q` equals the identity element, then `g` is a generator.

For more explanation on how this implementation works, refer to ([10]), ([13])
and ([14]).

#### Dual Receiver Key Generation: DRGen()

1. Pick random values `x1, x2, y1, y2, z` in Z_q.
2. Compute group elements
  - `C = G1*x1 + G2*x2`
  - `D = G1*y1 + G2*y2`
  - `H = G1*z`.
3. The public key is `PK = {C, D, H}` and the secret key is
   `sk = {x1, x2, y1, y2, z}`.

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
3. Compute symmetric key `K_enc = SHA3-256(K)`. K is hashed from 55 bytes to 32
   bytes because XSalsa20 has a maximum key size of 32 bytes.
4. Pick a random 24 bytes `nonce` and compute `phi = XSalsa20-Poly1305_K_enc(m,
   nonce)`
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
6. Send `gamma = (U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, phi)`.

#### Dual Receiver Decryption: DRDec(PK1, PK2, ski, gamma):

Let `{C1, D1, H1} = PK1`, `{C2, D2, H2} = PK2` and `{x1i, x2i, y1i, y2i, zi} =
ski`.
ski is the secret key of the person decrypting the message.

1. Parse `gamma` to retrieve components
  `(U11, U21, E1, V1, U12, U22, E2, V2, l, n1, n2, nonce, phi) = gamma`.
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
3. Recover symmetric key `K_enc = SHA3-256(Ei - U1i*zi)`. K is hashed from
   55 bytes to 32 bytes because XSalsa20 has a maximum key size of 32 bytes.
4. Decrypt `m = XSalsa20-Poly1305_K_enc(phi, nonce)`.

### ROM Authentication

The Authentication scheme consists of two functions:

`sigma = Auth(A_2, a_2, {A_1, A_2, A_3}, m)`, an authentication function.

`Verify({A_1, A_2, A_3}, sigma, m)`, a verification function.

#### Domain parameters

We reuse the previously defined generator in Cramer-Shoup of DRE:

```
G = (11781216126343694673728248434331006466518053535701637341687908214793940427
7809514858788439644911793978499419995990477371552926308078495, 19)

= (0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf393
2d94c63d96c170033f4ba0c7f0de840aed939f, 0x13)
```

#### Authentication: Auth(A2, a2, {A1, A2, A3}, m):

A2 is the public value associated with a2, that is, `A2 = G*a2`.
m is the message to authenticate.

1. Pick random values `t1, c2, c3, r2, r3` in Z_q.
2. Compute `T1 = G*t1`.
3. Compute `T2 = G*r2 + A2*c2`.
4. Compute `T3 = G*r3 + A3*c3`.
5. Compute `c = HashToScalar(G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)`.
6. Compute `c1 = c - c2 - c3 (mod q)`.
7. Compute `r1 = t1 - c1 * a2 (mod q)`.
8. Send `sigma = (c1, r1, c2, r2, c3, r3)`.

#### Verification: Verify({A1, A2, A3}, sigma, m)

1. Parse sigma to retrieve components `(c1, r1, c2, r2, c3, r3)`.
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

[1]: https://www.ietf.org/rfc/rfc3526.txt "M. Kojo: More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)"
[2]: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf "N. Unger, I. Goldberg: Improved Techniques for Implementing Strongly Deniable Authenticated Key Exchanges"
[3]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html "Off-the-Record Messaging Protocol version 3"
[4]: https://mikehamburg.com/papers/goldilocks/goldilocks.pdf "M. Hamburg: Ed448-Goldilocks, a new elliptic curve"
[5]: http://www.ietf.org/rfc/rfc7748.txt "A. Langley, M. Hamburg, and S. Turner: Elliptic Curves for Security.” Internet Engineering Task Force; RFC 7748 (Informational); IETF, Jan-2016"
[6]: https://whispersystems.org/docs/specifications/doubleratchet "Trevor Perrin (editor), Moxie Marlinspike: The Double Ratchet Algorithm"
[7]: https://whispersystems.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet  "Trevor Perrin (editor), Moxie Marlinspike: The Double Ratchet Algorithm"
[8]: https://tools.ietf.org/html/rfc3339 "G. Klyne, C. Newman: Date and Time on the Internet: Timestamps"
[9]: https://github.com/twstrike/otrv4/blob/master/gen_gens_ed448.py
[10]: https://ed25519.cr.yp.to/python/ed25519.py "Daniel Bernstein: ed25519"
[11]: https://eprint.iacr.org/2015/673.pdf "Mike Hamburg: Decaf: Eliminating cofactors through point compression"
[12]: https://whispersystems.org/docs/specifications/doubleratchet/#symmetric-key-ratchet "Trevor Perrin (editor), Moxie Marlinspike: The Double Ratchet Algorithm"
[13]: https://ed25519.cr.yp.to/ed25519-20110926.pdf "Daniel Bernstein, Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang: High-speed high-security signatures"
[14]: https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05 "S. Josefsson and I. Liusvaara: Edwards-curve Digital Signature Algorithm (EdDSA)"
