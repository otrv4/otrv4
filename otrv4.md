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
5. [Notation and parameters](#notation-and-parameters)
6. [Conversation Initialization](#conversation-initialization)
  1. [User Profile](#user-profile)
  2. [Creating an User Profile](#creating-an-user-profile)
  3. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
7. [Requesting conversation with older OTR versions](#requesting-conversation-with-older-otr-versions)
8. [Data exchange](#data-exchange)
  1. [Data Message](#data-message)
  2. [Revealing MAC Keys](#revealing-mac-keys)
  3. [Fragmentation](#fragmentation)
9. [The protocol state machine](#the-protocol-state-machine)
10. [Socialist Millionaires' Protocol (SMP)](#socialist-millionaires-protocol-smp)

[Appendices](#appendices)
  1. [ROM DRE](#rom-dre)
  2. [ROM Authentication](#rom-authentication)

## Main Changes over Version 3

- Improvements on security and privacy:
  - Security level raised to 224 bits based on elliptic curve cryptography
  - Additional protection against transcript decryption in the case of
    elliptic curve cryptography compromise
- The cryptographic primitives and protocols have been updated:
  - Deniable Authenticated Key Exchange using SPAWN.
  - Key management using the Double Ratchet Algorithm.
- SMP:
  - Upgraded the cryptographic primitives to use ECC based on the Edwards
    448 curve (Goldilocks).

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
channel are confidential and integrity is protected.

Both parties can deny that they have participated in a conversation. They can
also deny having sent any of the exchanged messages in the conversation. The
respective party can be certain of the authenticity of the messages but cannot
transfer this knowledge to someone else.

On the other hand, OTRv4 does not protect against an active attacker performing
Denial of Service attacks to reduce availability.

## Notation and parameters

This section contains information needed to understand the parameters, variables
and arithmetic used.

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
the above group, the operation should be done modulo the above prime.

### TLV Types

OTRv4 supports the same TLV record types from OTRv3.

### Data types

OTRv4 uses almost the same data types as specified in OTRv3 (bytes, shorts, ints, MPIs,
and DATA) except for CTR and MAC, and with the addition of:

```
Nonce (NONCE):
  24 byte data

ED448 point (POINT):
  56 byte unsigned value, big-endian

User Profile(USER-PROF):
  Detailed in ["User Profile Data Type" section](#user-profile-data-type)
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
    Where (c1, r1, c2, r2, c3, r3) = Auth(A_2, a_2, {A_1, A_2, A_3}, m)
```

### Public keys and fingerprints

OTRv4 introduces a new type of public-key:

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
SHA3-256 hash of the byte-level representation of the public key.

## Key management

In the DAKE, OTRv4 makes use of long-term Cramer-Shoup keys and ephemeral DH
keys.

For exchanging data messages, OTRv4 uses a key structure and key rotation
strategy with the [Double Ratchet] algorithm [6] at its core. As a result we
will use many of the terms within the Double Ratchet domain to describe the
difference in the context of OTRv4. A cryptographic ratchet is a one way
mechanism for deriving new cryptographic keys from previous keys. New keys
cannot be used to calculate the old keys. Its name comes from the mechanical
ratchet.

OTRv4 retains the Diffie-Hellman Ratchet [7] and Symmetric Key Ratchet [8] from
the algorithm.

OTRv4 adds new 3072 Diffie-Hellman keys called the Mix Key Pair. In addition,
another Diffie-Hellman Ratchet and Key Symmetric Ratchet is added for the Mix
Key alone. These were added to protect transcripts of data messages in the case
that elliptic curve cryptography is broken. During the DAKE, both parties agree
upon the first set of 3072 Diffie-Hellman keys. Then every third Diffie-Hellman
Ratchet in the Double Ratchet, a new 3072 key is agreed upon. Between each
Diffie-Hellman Mix Key Ratchet, both sides will conduct a Symmetric Mix Key
Ratchet.

In order to manage keys, each correspondent keeps track of:

As the ratchet moves forward through its keys, its state is kept with the
following values:

(TODO: the below should be consistent with our naming conventions, uppercase/lowercase)
```
State variables:
  initiator: the participant who should perform the first root key rotation after the DAKE completes.
  i: the current ratchet id.
  j: the last sent message id
  k: the last received message id.

Key variables:
  `root[i]`: the Root key for the ratchet i.
  `chain_s[i][j]`: the sending chain key for the message j in the ratchet i.
  `chain_r[i][k]`: the receiving chain key for the message k in the ratchet i.
  `our_ecdh`: our current ECDH ephemeral key pair.
  `their_ecdh`: their ECDH ephemeral public key.
  `our_dh`: our DH ephemeral key pair
  `their_dh`: their DH ephemeral public key
  `dh_shared_secret`: the shared secret previously computed.
```

The previously mentioned variables are affected by these events:

* When you send a DAKE message (starting a new DAKE).
* Upon completing the DAKE.
* When you send a Data Message.
* When you receive a Data Message.

TODO: what happens to state machine When you receive a Query message
TODO: what happens to state machine When you receive an End conversation message
TODO: what happens to state machine When you receive an Error message

### Calculating Keys

This section describes the functions used to manage the key material.

#### Ratcheting the ECDH keys

The participant invoking this is moving into a new ECDH ratchet. The next data
message will advertise a new ratchet (`i + 1`) from the receiver perspective.

When you ratchet the ECDH keys:

* Securely delete `our_ecdh`.
* Generate a new ECDH key pair and assign it to `our_ecdh = generateECDH()`. See [generateECDH()](#ECDH-and-DH-Shared-Secrets).
* Increment the current ratchet id (`i`) by 1.
* Reset the next sent message id (`j`) to 0.

#### Calculating the DH shared secret

If this ratchet is a multiple of three:

  * Securely delete `our_dh`.
  * Generate a new DH key pair and assign it to `our_dh = generateDH()`. See [generateDH()](#ECDH-and-DH-Shared-Secrets).
  * Calculate a `dh_shared_secret = SHA3-256(DH(our_dh, their_dh)`.

Otherwise:

  * Derive a `dh_shared_secret = SHA3-256(dh_shared_secret)`.

#### ECDH and DH Shared Secrets

```
generateECDH()
  pick a random value r from Z_q
  return pubECDH = G2 * r, secretECDH = r

generateDH()
  pick a random value r (640 bits)
  return pubDH = g3 ^ r, secretDH = r

K_ecdh = (G1*x)*y (POINT)
  The shared ECDH key.

k_dh = (g3^a)^b mod p (MPI)
  The shared 3072-bit DH key.
```

#### Mixing ECDH and DH Shared Secrets

```
calculate_shared_secret(K_ecdh, k_dh):
  serialized_K_ecdh = serialize_point(K_ecdh)
  serialized_k_dh = serialize_MPI(k_dh)
  K = SHA3-512(serialized_K_ecdh, serialized_k_dh)
  return K
```

#### Calculate Double Ratchet Keys

```
calculate_ratchet_keys(K):
  n = the ratchet_id you are creating keys for
  root[n] = SHA3-512(0x01 || K)
  chain_s[n][0] = SHA3-512(0x02 || K)
  chain_r[n][0] = SHA3-512(0x03 || K)
  return R, decide_between_chain_keys(Ca, Cb)
```

#### Decide Between Chain Keys

Both sides will compare their public keys to choose a chain key for sending and receiving:
- Alice (and similarly, Bob) determines if she is the "low" end or the "high" end of this ratchet.
If Alice's ephemeral ECDH public key is numerically greater than Bob's public key, then she is the "high" end.
Otherwise, she is the "low" end.
- Alice selects the chain keys for sending and receiving:
  - If she is the "high" end, set `initiator` as `true`, use Ca as the sending
  chain key (`chain_s`) and Cb as the receiving chain key (`chain_r`).
  - If she is the "low" end, set `initiator` as `false`, use Cb as the sending
  chain key (`chain_s`) and Ca as the receiving chain key (`chain_r`).

```
decide_between_chain_keys(Ca, Cb):
  if compare(our_ecdh.public, their_ecdh) > 0
    return Ca, Cb
  else
    return Cb, Ca
```

### Deriving new chain keys

When sending data messages, you must derive the chain key:

```
derive_chain_key(C, i, j):
  C[i][j] = SHA3-512(C[i][j-1])
```

### Retrieve chain keys

When receiving data messages, you must retrieve the chain key:

```
retrieve_chain_key(C, i, k):
  if C[i][k] not exist:
  C[i][k] = SHA3-512(retrieve_chain_key(C, i, k-1))
```

### Calculate Encryption and MAC keys

When sending or receiving data messages, you must calculate the message keys:

```
derive_enc_mac_keys(chain_key):
  Kenc = SHA3-256(0x00 || chain_key)
  Kmac = SHA3-512(0x01 || chain_key)
  return MKenc, Kmac
```

## Conversation Initialization

OTRv4 will initialize through a Query message or a whitespace tag, as discussed
in OTRv3 [3]. After this, the conversation is authenticated using a deniable
authenticated key exchange (DAKE). The conversation can also start directly
with the first message of the DAKE, without a Query message or a whitespace tag.

### Requesting conversation with older OTR versions

Bob might respond to Alice's request or notification of willingness to start a
conversation using OTRv3. If this is the case and Alice supports the version 3,
the protocol falls back to OTRv3 [3]. If Alice does not support version 3, then
this message is ignored.

## User Profile

OTRv4 introduces mandatory user profile publication in a public place. The user
profile contains the Cramer-Shoup long term public key, signed version support
information, and a signed profile expiration date. Both parties will include
the user profile in the beginning of the DAKE. The frequency of the user
profile publication is determined by its expiration and renewal policy.

### Creating an User Profile

To create a user profile, assemble:

1. Cramer-Shoup key-pair
2. Version: a string corresponding to the user's supported OTR versions.
   The format is described in OTRv3 under the section "OTR Query Messages".
   [3]
3. Profile Expiration: This is the date the profile expires. It contains the
   amount of seconds from the epoch to the expiration date. Its format is the
   same as the "date-time" described in section 5.6 of RFC3339 [8].
4. Profile Signature: One of the Cramer-Shoup secret key values (`z`) and its
   generator (`G1`) is used to create signatures of the entire profile. It is
   created using the Ed448 signature algorithm as documented in [4].
5. (optional) Transition Signature of the profile by the user's OTRv3 DSA key:
   A transitional signature that enables contacts that trust user's version 3
   DSA key to trust the user's profile in version 4. This is only used if the
   user supports version 3 and 4.

Then this profile must be published in a public place, like an untrusted
server.

#### Renewing a Profile

If a renewed profile is not published in a public place, and if the only
publicly available profile is expired, the user's participation deniability is at risk.

Before the profile expires, the user must publish an updated profile with a new
expiration date. The client establishes the frequency of expiration - this can
be configurable. A recommended value is two weeks.

#### User Profile Data Type

```
User Profile (USER-PROF):
  Cramer-Shoup key (CRAMER-SHOUP-PUBKEY)
  Version (VER)
  Version Expiration (PROF-EXP)
  Profile Signature (MPI)
  (optional) Transitional Signature (MPI)

Version (VER):
  1 byte unsigned len, big-endian
  len byte unsigned value, big-endian

Version Expiration (PROF-EXP):
  64-bit signed value, big-endian
```

### Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the Deniable Authenticated Key Exchange. This is a
way to mutually agree upon a shared key for the two parties and authenticate one another
while providing participation deniability.

This protocol is derived from the [Spawn protocol][2], which uses dual-receiver
encryption (DRE) and a non-interactive zero-knowledge proof of knowledge
(NIZKPK) for authentication (Auth).

Alice long-term Cramer-Shoup key-pair is `SKa = (x1a, x2a, y1a, y2a, za)` and
`PKa = (Ca, Da, Ha)`. Bob long-term Cramer-Shoup key-pair is `SKb = (x1b, x2b,
y1b, y2b, zb)` and `PKb = (Cb, Db, Hb)`. Both key pairs are generated by
`DRGen()`.

#### Overview

```
a, b: DH ephemeral secret key
A, B: DH ephemeral public key
k_dh: mix-key, a shared secret computed from a DH exchange = A^b, B^a

x, y: ECDH ephemeral secret key
X, Y: ECDH ephemeral public key = G1*x, G1*y
K_ecdh: a shared secret computed from an ECDH exchange = X*y, Y*x
```

```
Alice                                    Bob
---------------------------------------------------
Query Message or Whitespace Tag ------->
                                <------- Prekey (ψ1)
                  DRE-Auth (ψ2) ------->
                                         Verify & Decrypt (ψ2)
```

Bob will be initiating the DAKE with Alice.

**Bob:**

1. Generates an ephemeral ECDH secret key `y` and a public key `Y`.
2. Generates an ephemeral 3072-bit DH secret key `b` and a public key `B`.
    ```Details
    * Set `prev_our_ecdh` as your current ECDH key pair (`our_ecdh`), if you have it.
    * Set `our_ecdh` as our ECDH ephemeral key pair from the DAKE (`(y, Y)`).
    * Set `our_dh` as our DH ephemeral key pair from the DAKE (`b`, `B`).
    * Set `j = 1` because the pre-key message is considered the first in this DH ratchet.
    * Increase ratchet id `i = i + 1`.
    ```
3. Sends Alice a pre-key message `ψ1 = ("Prof_B", Y, B)`. Prof_B is
   Bob's User Profile.

**Alice:**

1. Generates an ephemeral ECDH secret key `x` and a public key `X`.
2. Generates an ephemeral 3072-bit DH secret key `a` and a public key `A`.
3. Computes `γ = DREnc(PKa, PKb, m)`, being `m = "Prof_B" || "Prof_A" || Y || X || B || A`.
   Prof_A is Alice's User Profile.
4. Computes `σ = Auth(Ha, za, {Ha, Hb, Y}, "Prof_B" || "Prof_A" || Y || B || γ)`.
5. Computes root level keys (`root[0]`, `chain_s`, and `chain_r`).
    ```Details
    * Set `prev_our_ecdh` as your current ECDH key pair (`our_ecdh`), if you have it.
    * Set `our_ecdh` as our ECDH ephemeral key pair from the DAKE (`(x, X)`).
    * Set `our_dh` as our DH ephemeral key pair from the DAKE (`a`, `A`).
    * Set `their_ecdh` as their ECDH ephemeral public key from the DAKE (`Y`).
    * Set `their_dh` as their DH ephemeral public key from the DAKE (`B`).
    * Increase ratchet id `i = i + 1`.
    ```
6. Sends Alice a DRE-Auth Message `ψ2 = ("R", γ, σ)`.
7. At this point, the DAKE is complete for Alice and she:
    ```Details
    * Set `j = 0` to cause a DH-ratchet the next time a msg is sent.
    * Increase ratchet id `i = i + 1`.
    ```

**Bob:**

1. Verifies `Verify({Hb, Ha, Y}, σ, “Prof_B” || “Prof_A” || Y || B || γ)`.
2. Decrypts `m = DRDec(PKb, PKa, SKb, γ)`.
3. Verifies the following properties of the decrypted message `m`:
  1. The message is of the correct form (e.g., the fields are of the expected length).
     If any of the verifications fail, the message is ignored.
  2. Alice's identifier is the first one listed
  3. Bob's identifier is the second one listed, and it matches the identifier
     transmitted outside of the ciphertext
  4. `(Y, B)` is a prekey that Bob previously sent and remains unused.
4. Computes root level keys (`root[0]`, `chain_s`, and `chain_r`).
5. At this point, the DAKE is complete for Bob and he:
    ```Details
    * Set `their_ecdh` as their ECDH ephemeral public key from the DAKE (`X`).
    * Set `their_dh` as their DH ephemeral public key from the DAKE (`A`).
    * Increase ratchet id `i = i + 1`.
    ```

#### After completing the DAKE

Regardless of who you are:

* Calculate `our_ecdh` and `our_dh`.
* Securely erase `our_ecdh.private` and `our_dh` key pair.
* Calculate the ECDH shared secret `K_ecdh = (G1*x)*y`.
* Calculate the DH shared secret `k_dh = (g3*a)*b`.
* Calculate `K = calculate_shared_secret(K_ecdh, k_dh)`.
* Calculate the SSID from shared secret: it is the first 64 bits of `SHA3-256(0x00 || K)`.
* Calculate the first set of keys with `root[0], chain_s[0][0], chain_r[0][0] = calculate_ratchet_keys(K)`.

#### Pre-key message

This is the first message of the DAKE. Bob sends it to Alice to commit to a
choice of DH and ECDH key. A valid Pre-key message is generated as follows:

1. Create a user profile, as detailed [here](#creating-a-user-profile)
2. Choose a random ephemeral ECDH key pair:
  * secret key `x`, which is a random element from `Z_q` (448 bits).
  * public key `X`
3. Generates an ephemeral DH secret key pair:
  * secret key `a` (640 bits).
  * public key `A = g3 ^ a`.

A pre-key is an OTR message encoded as:

(TODO: we should check the message types and see if we can create good encodings for the Base64, just like we have for OTRv3)
```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x01.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For a pre-key message, this will often be 0
  since the other party may not have identified its instance tag yet.
Sender's User Profile (USER-PROF)
  As described in the section 'Creating a User Profile'.
X (POINT)
  The ephemeral public ECDH key.
A (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase, this is NOT a POINT.
```

#### DRE-Auth message

This is the second message of the DAKE. Alice sends it to Bob to commit to a
choice of her ECDH ephemeral key and her DH ephemeral key, and acknowledgement
of Bob's ECDH ephemeral key and DH ephemeral key. The ECDH ephemeral public keys
and DH ephemeral public keys are encrypted with DRE and authenticated with a
NIZKPK.

A valid DRE-Auth message is generated as follows:

1. Create an user profile, as detailed [here]
   (#creating-a-user-profile)
2. Choose a random ephemeral ECDH key pair:
  * secret key `y`, which is a random element from `Z_q` (448 bits).
  * public key `Y`
3. Generates an ephemeral DH secret key pair:
  * secret key `b` (640 bits).
  * public key `B = g3 ^ b`.
4. Generate `m = X || Y || A || B`
5. Compute `DREnc(PKa, PKb, m)` and serialize it as a DRE-M value in the variable `γ`.
6. Compute `σ = Auth(Ha, za, {Ha, Hb, Y}, "Prof_B" || "Prof_A" || Y || B || γ)`.

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
  As described in the section 'Creating a User Profile'.
Y (POINT)
  The ephemeral public ECDH key.
B (MPI)
  The ephemeral public DH key. Note that even though this is in uppercase, this is NOT a POINT.
γ (DRE-M)
  The Dual-receiver encrypted value.
σ (AUTH)
  The Auth value.
```

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange [data messages](#data-message) initialized with the shared
secret established in the DAKE.

A message with an empty human-readable part (the plaintext is of zero length, or
starts with a NUL) is a "heartbeat" packet, and should not be displayed to the
user (but it is still useful for key rotations).

```
Alice                                                                           Bob
-----------------------------------------------------------------------------------
Initialize root key, chain keys                        Initialize root key, chain keys
Generate K_ecdh, X, x                                  Generate K_ecdh, Y, y
Generate k_dh, A, a                                    Generate k_dh, B, b
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

### Data Message

This message is used to transmit a private message to the correspondent.
It is also used to [reveal old MAC keys](#revealing-mac-eys).

#### Data Message format

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

    Ratchet id ratchet_id (INT)
      Must be strictly greater than 0, and increment by 1 with each ratchet.
      This should be set as sender's i.

    Message id message_id (INT)
      Must be strictly greater than 0, and increment by 1 with each message.
      This should be set with sender's j.

    Public ECDH Key (POINT)
      The sender's current ratchet ECDH public key.
      This should contain the value of our_ecdh.public_key variable.

    Public DH Key (MPI)
      The sender's current ratchet DH public key.
      This should contain the value of our_dh.public_key variable.
      You should send a NULL value if i % 3 != 0.
      NULL is 4 bytes length as 0x00000000

    Nonce (NONCE)
      The nonce used with XSalsa20 to create the encrypted message contained in
      this packet.

    Encrypted message (DATA)
      Using the appropriate encryption key (see below) derived from the
      sender's and recipient's DH public keys (with the keyids given in this
      message), perform XSalsa20 encryption of the message. The nonce used for
      this operation is also included in the header of the data message packet.

    Authenticator (MAC)
      The SHA3 MAC with the appropriate MAC key (see below) for everything:
      from the protocol version to the end of the encrypted message.

    Old MAC keys to be revealed (DATA)
      See Revealing MAC Keys section

#### When you send a Data Message:

In order to send a data message, a key is required to encrypt it. This key
will be derived from the previous chain key and, if the message's counter `j`
has been reset to zero, keys should be rotated.

Given a new ratchet:

  * Ratchet the ECDH keys. See "Ratcheting the ECDH keys" section.
  * Calculate ECDH secret by using `our_ecdh` and `their_ecdh`.
  * Calculate the `dh_shared_secret`.
  * Calculate the `mix key` by `ECDH(our_ecdh, their_ecdh) || dh_shared_secret`
  * Derive new set of keys `root[i]`, `chain_s[i][j]`, `chain_r[i][j]` from `mix key`.
  * Securely delete the root key and all chain keys from the ratchet `i-2`.
  * Securely delete the `mix key` and the `dh_shared_secret`.

Otherwise:

  * Increment last sent message ID `j = j+1`.
  * Derive the next sending chain Key `derive_chain_key(chain_s, i, j)`.
  * Securely delete `chain_s[i][j-1]`.

In any event:

1. Calculate the encryption key (`MKenc`) and the mac key (`MKmac`):

   ```
   MKenc, MKmac = derive_enc_mac_keys(chain_s[i][j])
   ```

2. Use the encryption key to encrypt the message and the mac key to calculate its MAC:

   ```
   Nonce = generateNonce()
   Encrypted_message = XSalsa20_Enc(MKenc, Nonce, m)
   Authenticator = SHA3-512(MKmac || Encrypted_message)
   ```

3. Forget and reveal MAC keys. The conditions for revealing MAC keys is stated
in the [Revealing MAC keys](#revealing-mac-keys) section.

#### When you receive a Data Message:

Use the `message_id` to compute the receiving chain key, and calculate encryption and mac keys.

```
  retrieve_chain_key(chain_r, ratchet_id, message_id)
  MKenc, MKmac = derive_enc_mac_keys(chain_r[ratchet_id][message_id])
```

Use the "mac key" (`MKmac`) to verify the MAC of the message.

If the message verification fails, reject the message.

Otherwise:

  * Decrypt the message using the "encryption key" (`MKenc`) and securely delete it.
  * Securely delete receiving chain keys older than `message_id-1`.
  * Set `j = 0` to indicate that a new DH-ratchet should happen the next time you send a message.
  * Set `their_ecdh` as the "Next Public ECDH key" from the message.
  * Set `their_dh` as the "Next Public DH Key" from the message, if it
    is not NULL.
  * Add the MKmac key to list of pending MAC keys to be revealed.

### Revealing MAC Keys

We reveal old MAC keys to provide forgeability of messages. Old MAC keys are
keys for already received messages and, therefore, will no longer be
used to verify the authenticity of the message.

MAC keys are revealed with data messages. They are also revealed with heartbeat
messages (data messages that encode a plaintext of zero length) if the receiver
has not sent a message in a configurable amount of time. Put them (as a set
of concatenated 64-byte values) into the "Old MAC keys to be revealed" section
of the next Data Message you send.

A receiver can reveal a MAC key in the following case:

- the receiver has received a message and has verified the message's authenticity
- the receiver has discarded associated message keys
(TODO: is this an AND or an OR condition?)

### Fragmentation

Some networks may have a `maximum message size` that is too small to contain an
encoded OTR message. In that event, the sender may choose to split the message
into a number of fragments. This section describes the format of the fragments.

OTRv4 has the same message fragmentation as OTRv3 without compatibility with version 2.
This means that fragmentation is performed in OTRv4 in the same why as specified in OTRv3:
the format is the same so you will have to wait for reassembly to finalize,
to deal with a message.

All OTRv4 clients must be able to assemble received fragments, but performing
fragmentation on outgoing messages is optional.

#### Transmitting Fragments

If you have information about the `maximum message size` you are able to send
(the different IM networks have different limits), you can fragment an encoded
OTR message as follows:

  * Start with the OTR message as you would normally transmit it. For example, a
Data Message would start with `?OTR:AAQD` and end with `.`.
  * Break it up into sufficiently small pieces. Let this number of pieces be `total`,
and the pieces be `piece\[1\],piece\[2\],...,piece[total]`.
  * Transmit `total` OTRv4 fragmented messages with the following structure:

  ```
  ?OTR|sender_instance|receiver_instance,index,total,piece[index],
  ```

The message should begin with `?OTR|` and end with `,`.

Note that `index` and `total` are unsigned short ints (2 bytes), and each has a
maximum value of 65535. Also, each `piece[index]` must be non-empty.
The instance tags, `index` and `total` values may have leading zeroes.

Note that fragments are not messages that can be fragmented: you can't fragment
a fragment.

####Receiving Fragments:

If you receive a message containing `?OTR|` (note that you'll need to check for
this _before_ checking for any of the other `?OTR:` markers):

  * Parse it, extracting instance tags, `index`, `total`, and `piece[index]`.
  * Discard illegal fragment, if:
       * the recipient's own instance tag does not match the listed receiver instance tag
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

After this, if stored `total` is bigger than 0 and stored `index` is equal to stored `total`,
treat piece as the received message.

If you receive a non-OTR message, or an unfragmented message, forget any stored
value you may have (`piece`, `total` and, `index`).

For example, here is a Data Message we would like to transmit over a network with
an unreasonably small `maximum message size`:

    ?OTR:AAQD--here-is-my-very-long-message.

We could fragment this message into three pieces:

    ?OTR|5a73a599|27e31597,00001,00003,?OTR:AAQD--here,
    ?OTR|5a73a599|27e31597,00002,00003,is-my-very-long,
    ?OTR|5a73a599|27e31597,00003,00003,-message,

## The protocol state machine

An OTR client maintains separate state for every correspondent. For example,
Alice may have an active OTR conversation with Bob, while having an insecure
conversation with Charlie. This state machine consists of two main state
variables, as well as some other information (such as encryption keys). The two
main state variables are:

### Message state

The message state variable, `msgstate`, controls what happens to outgoing
messages typed by the user. It can take one of three values:
(TODO: this way of talking about msgstate is very implementation specific. Do we need it? Can we express it in less "computery" terms?)

```
MSGSTATE_PLAINTEXT
    This state indicates that outgoing messages are sent without encryption.
    and it is used before an OTR conversation is initiated. It is the initial
    state, and the only way to subsequently enter this state is for the user
    to explicitly request it via an UI operation.

MSGSTATE_ENCRYPTED
    This state indicates that outgoing messages are sent encrypted and it is
    used during an OTR conversation. The only way to enter this state is for
    the authentication state machine (below) to be successfully completed.

MSGSTATE_FINISHED
    This state indicates that outgoing messages are not delivered at all.
    It is entered only when the other party indicates his side of the OTR
    conversation has finished. For example, if Alice and Bob are having an OTR
    conversation, and Bob instructs his OTR client to end its private session
    with Alice (by logging out, for example), Alice will be notified of this,
    and her client will switch to MSGSTATE_FINISHED mode. This prevents Alice
    from accidentally sending a message to Bob in plaintext (consider what
    happens if Alice was in the middle of typing a private message to Bob when
    he suddenly logs out, just as Alice hits Enter).
```

### Authentication state

The authentication state variable, `authstate`, controls the aunthentication
mechanism. It can take one of two values:

```
AUTHSTATE_NONE
    This state indicates that the authentication protocol is not currently in
    progress. This is the initial state.

AUTHSTATE_AWAITING_DRE_AUTH
    After Bob initiates the authentication protocol by sending Alice the Pre-
    key Message, he enters this state until Alice replies.
```

### Policies
(TODO: why are policies inside of the state machine??)
(TODO: do these policies belong in the spec? They seem to be implementation specific. Maybe we can have an implementation suggestions section instead?)

OTR clients can set different policies for different correspondents. For
example, Alice could set up her client so that it speaks version 4 of the OTR
protocol. Nevertheless, she may also add an exception for Charlie, who she knows
talks through a client that runs an old version of the protocol. Therefore, the
client will start the appropiate OTR conversation in correspondace with the
other side, or will refuse to send non-encrypted messages to Bob.

The policies that can be set (on a global or per-correspondent basis) are any
combination of the these boolean flags:

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
// TODO: elaborate on this.
It is possible for UIs to simply offer old "combinations" of options, and not
ask for them separately.

### State transitions

An OTRv4 client must handle these ten events:

User events:
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

(TODO: maybe we should also mention that we need to handle the case of any OTRv3 message arriving)

The following sections will outline which actions to take for each case. They
all assume that at least `ALLOW_V3` or `ALLOW_V4` is set; if not, then OTR is
completely disabled and no special handling of messages should be done. Version
1 and 2 messages are out of the scope of this specification.

For version 3 and 4 messages, if the receiving instance tag is not equal to its
own, the message should be discarded and the user optionally warned.

The exception here is the DH Commit Message where the recipient instance tag may
be 0, which indicates that no particular instance is specified.

#### User requests to start an OTR conversation

* Send an OTR Query Message to the correspondent.

#### Receiving plaintext without the whitespace tag

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * Simply display the message to the user.
  * If `REQUIRE_ENCRYPTION` is set, warn the user that the message was received
    unencrypted.

If `msgstate` is `MSGSTATE_ENCRYPTED` or `MSGSTATE_FINISHED`:

  * Display the message to the user.
  * Warn the user that the message was received unencrypted.

#### Receiving plaintext with the whitespace tag

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * Remove the whitespace tag and display the message to the user.
  * If `REQUIRE_ENCRYPTION` is set, warn the user that the message was received
    unencrypted.

If `msgstate` is `MSGSTATE_ENCRYPTED` or `MSGSTATE_FINISHED`:

  * Remove the whitespace tag and display the message to the user.
  * Warn him that the message was received unencrypted.

In any event, if `WHITESPACE_START_DAKE` is set:

If the tag offers OTR version 4 and `ALLOW_V4` is set:

  * Send a pre-key Message.
  * Transition `authstate` to `AUTHSTATE_AWAITING_DRE_AUTH`.

If the tag offers OTR version 3 and `ALLOW_V3` is set:

  * The protocol proceeds as specified in OTRv3.

#### Receiving a Query Message

If the query message offers OTR version 4 and `ALLOW_V4` is set:

  * Send a Pre-key Message
  * Transition `authstate` to `AUTHSTATE_AWAITING_DRE_AUTH`.

If the query message offers OTR version 3 and `ALLOW_V3` is set:

  * The protocol proceeds as specified in OTRv3.

#### Receiving an Error Message

  * Display the message to the user.
  * If `ERROR_START_DAKE` is set, reply with a Query Message.
  * Reset `msgstate` to `MSGSTATE_PLAINTEXT` and `authstate` to `AUTHSTATE_NONE`

#### Receiving a Pre-key message

If the message is version 4 and `ALLOW_V4` is not set

  * Ignore this message.

If `authstate` is `AUTHSTATE_AWAITING_DRE_AUTH`:

This indicates that you have sent a Pre-key message to your correspondent and that either she didn't receive it or didn't receive it yet; but has sent you one
as well.

The symmetry will be broken by comparing the hashed `X` you sent in your pre-key
with the one you received, considered as 32-byte unsigned big-endian values.

If yours is the lower hash value:

  * Ignore the incoming pre-key message.

Otherwise:

  * Forget your old `X` value that you sent earlier.

Regardless of `authstate` value, if you haven't ignored the incoming pre-key
message, you should:

  * Verify that the user profile signature is valid.
  * Verify that the user profile is not expired.
  * Verify that the point `X` received in the pre-key message is on curve 448.
  * Verify that the DH public key is from the correct group.

If everything checks out:

  * Reply with a DRE-Auth Message.
  * Compute the ECDH shared secret `K_ecdh = (G1*x)*y`.
  * Compute the DH shared secret `k_dh = (g3*a)*b`.
  * Transition `authstate` to `AUTHSTATE_NONE`.
  * Transition `msgstate` to `MSGSTATE_ENCRYPTED`.
  * Initialize the double ratcheting.
  * If there is an stored message, encrypt it and send it as a Data Message.

#### Receiving a DRE-Auth message

If the message is version 4 and `ALLOW_V4` is not set

  * Ignore this message.

If `authstate` is `AUTHSTATE_AWAITING_DRE_AUTH`:

  * Verify that the profile signature is valid.
  * Verify that the profile is not expired.
  * If the auth σ is valid, decrypt the DRE message and verify:
    * that the point Y received in the pre-key message is on curve 448.
    * that the B DH public key is from the correct group.

If everything verifies:

  * Compute the ECDH shared secret `K_ecdh = (G1*y)*x`.
  * Compute the DH shared secret `k_dh = (g3*b)*a`.
  * Transition `authstate` to `AUTHSTATE_NONE`.
  * Transition `msgstate` to `MSGSTATE_ENCRYPTED`.
  * Initialize the double ratcheting.
  * If there is an stored message, encrypt it and send it as a Data Message.

Otherwise:

  * Ignore the message. This may cause the sender to be in an invalid
  `msgstate` equals `MSGSTATE_ENCRYPTED`. This can be detected as soon as she
  tries to send a next data message as it would not be possible to decrypt it
  and an OTR error message will be replied.

#### User types a message to be sent

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * If `REQUIRE_ENCRYPTION` is set:
    * Store the plaintext message for possible retransmission and send a Query Message.
    * TODO: How are going to handle subsequent occurences of this case?
      Should we simply flood the user with Query Messages until the DAKE ends?
  * Otherwise:
    * If `SEND_WHITESPACE_TAG` is set, and you have not received a plaintext message from this correspondent since last entering `MSGSTATE_PLAINTEXT`, attach the whitespace tag to the message. Send the (possibly modified) message as plaintext. // TODO: does this mean we should keep a log on this state machine transitions?

If `msgstate` is `MSGSTATE_ENCRYPTED`:

  * Encrypt the message, and send it as a Data Message.

If `msgstate` is `MSGSTATE_FINISHED`:

  * Inform the user that the message cannot be sent at this time.
  * Store the plaintext message for possible retransmission.
  * Return to `MSGSTATE_PLAINTEXT`
  * Return to `AUTHSTATE_NONE`
  * Send Query Message.

#### Receiving a Data Message

If `msgstate` is `MSGSTATE_ENCRYPTED`:

Verify the information in the message. If the verification succeeds:

  * Decrypt the message and display the human-readable part (if non-empty) to the user. // TODO: if empty what does it mean?
  * Rotate root, chain and mix keys as appropiate.
  * If you have not sent a message to this correspondent in some (configurable) time, send a "heartbeat" message. // TODO: what is the configurable time?

If the received message contains a TLV type 1:
(TODO: in what order should TLVs be processed? Should we end the conversation immediately, or do other things first?)

  * Forget all encryption keys for this correspondent, and transition `msgstate` to `MSGSTATE_FINISHED`.

Otherwise:
(TODO: this otherwise seems to be if the data message doesn't contain TLV type 1, which is incorrect)

  * Inform the user that an unreadable encrypted message was received, and reply with an Error Message.

If `msgstate` is `MSGSTATE_PLAINTEXT` or `MSGSTATE_FINISHED`:

   * Inform the user that an unreadable encrypted message was received, and reply with an Error Message.

#### User requests to end an OTR conversation

If `msgstate` is `MSGSTATE_PLAINTEXT`:

  * Do nothing.

If `msgstate` is `MSGSTATE_ENCRYPTED`:

  * Send a Data Message containing a TLV type 1.
  * Transition `msgstate` to `MSGSTATE_PLAINTEXT`.

If `msgstate` is `MSGSTATE_FINISHED`:

  * Transition `msgstate` to `MSGSTATE_PLAINTEXT`.
(TODO: is this correct? I thought ending an OTR conversation should always transition to finished?)

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

Handling a new DAKE as a new DH ratchet (and simply incrementing j) should fix
this by applying the same approach as OTRv3: a new DAKE is considered simply as
a new key exchange.

Another suggested alternative is breaking the OTR channel (by reseting the
`msgstate` variable) at the moment you engage in a new DAKE (a new ψ1 is either
sent of received). This can lead to problems of sending messages unencrypted
unless all the participants have the `REQUIRE_ENCRYPTION` policy.


## Socialist Millionaires Protocol (SMP)

SMP in version 4 shares the same TLVs and flow as SMP in OTRv3 with the
following exceptions.

OTRv4 uses Ed448 as the cryptographic primative. This changes the way values
are serialized and how they are computed. OTRv4 also reuses the SMP Message 1Q
with TLV type 7 for situations where a user question is sent and when it is not
sent. In cases where the question is not present, the user-speicified DATA
portion of the secret has length 0 and value NUL. Lastly, OTRv4 creates
fingerprints using SHA3-256. Thus, the size of the fingerprint in the "Secret
Information" section of OTRv3 [3] should be 32 bytes in size.

(TODO: the section on the question and TLV type 7 is weird)

To define the SMP values under Ed448, we reuse the previously defined generator
for Cramer-Shoup:

`G = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862,
44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)`

TODO: Use the correct annotations for this (upper case for points, lower case
for integers)

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

#### SMP message 1Q

SMP message 1Q is sent by Alice to begin a DH exchange to determine two new
generators, `g2` and `g3`. A valid  SMP message 1 is generated as follows:

1. Determine her secret input `x`, which is to be compared to Bob's secret `y`, as specified in the "Secret Information" section.
2. Pick random values `a2` and `a3` (448 bits) in `Z_q`. These will be Alice's exponents for the DH exchange to pick generators.
3. Pick random values `r2` and `r3` (448 bits) in `Z_q`. These will be used to generate zero-knowledge proofs that this message was created according to the protocol.
4. Compute `G2a = G*a2` and `G3a = G*a3`.
5. Generate a zero-knowledge proof that the value a2 is known by setting `c2 = HashToScalar(1 || G*r2)` and `d2 = r2 - a2 * c2 mod q`.
6. Generate a zero-knowledge proof that the value a3 is known by setting `c3 = HashToScalar(2 || G*r3)` and `d3 = r3 - a3 * c3 mod q`.
7. Store the values of `x`, `a2` and `a3` for use later in the protocol.


The SMP message 1Q has the following data:

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


The SMP message 2 has the following data:

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

The SMP message 3 has the following data:

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

The SMP message 4 has the following data:

```
Rb (POINT)
  This value is used in the final comparison to determine if Alice and Bob share the same secret.

cR (MPI), d7 (MPI)
  A zero-knowledge proof that Rb was created according to the protocol given above.
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
    4. Check that `cP = HashToScalar(5 || G3*d5 + Pb*cP || G*d5 + G2*d6 + Qb*cP)`.
* Create SMP message 3 and send it to Bob.
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

* Verify Bob's zero-knowledge proof for Rb:
   1. Check that `Rb` is `>= 2` and `<= modulus-2`.
   2. Check that `cR = HashToScalar(8 || G1*d7 G3*cR || (Qa / Qb)*d7 + Rb*cR)`.

* Check whether the protocol was successful:
    1. `Compute Rab = Rb*a3`.
    2. Determine if `x = y` by checking the equivalent condition that `(Pa / Pb) = Rab`.

Set smpstate to `SMPSTATE_EXPECT1`, as no more messages are expected from Bob.

## Appendices

### ROM DRE

The DRE scheme consists of three functions:

`PK, SK = DRGen()`, a key generation function.

`γ = DREnc(PK1, PK2, m)`, an encryption function.

`m = DRDec(PK1, PK2, SKi, γ)`, a decryption function.

#### Domain parameters

The Cramer-Shoup scheme uses a group (`G`, `q`, `G1`, `G2`). This is a group with the same `q` as Curve 448. The generators `G1` and `G2` are:

```
G1 = (5014593412122187483175733622392028030242298988836581229127722326504735507
86782902904842340270909267251001424253087988710625934010181862,
4473149076155628025590544618523889049395342027715545953968190802002281485204547
3906622513423589000065035233481733743985973099897904160)

G2 = (1178121612634369467372824843433100646651805353570163734168790821479394042
77809514858788439644911793978499419995990477371552926308078495, 19)

```
(TODO: we need to specify how these values were generated)

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
3. Compute `K_enc = SHA3-256(K)`. K is compressed from 446 bits to 256 bits because XSalsa20 has a maximum key size of 256.
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
3. Recover secret key `K_enc = SHA3-256(Ei - U1i*zi)`. K is compressed from 446 bits to 256 bits because XSalsa20 has a maximum key size of 256.
4. Decrypt `m = XSalsa20-Poly1305_K_enc(φ, nonce)`.

### ROM Authentication

The Authentication scheme consists of two functions:

`σ = Auth(A_2, a_2, {A_1, A_2, A_3}, m)`, an authentication function.

`Verify({A_1, A_2, A_3}, σ, m)`, a verification function.

(TODO: the above Auth invocation is incorrect, we need to give it three public keys)
#### Domain parameters

We reuse the previously defined generator in Cramer-Shoup of DRE:

```
G = (501459341212218748317573362239202803024229898883658122912772232650473550786
782902904842340270909267251001424253087988710625934010181862,
44731490761556280255905446185238890493953420277155459539681908020022814852045473
906622513423589000065035233481733743985973099897904160).
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
8. Send `σ = (c1, r1, c2, r2, c3, r3)`.

#### Verification: Verify({A1, A2, A3}, σ, m)

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

[1]: https://www.ietf.org/rfc/rfc3526.txt "M. Kojo: More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)"
[2]: http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf "N. Unger, I. Goldberg: Improved Techniques for Implementing Strongly Deniable Authenticated Key Exchanges"
[3]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html "Off-the-Record Messaging Protocol version 3"
[4]: https://mikehamburg.com/papers/goldilocks/goldilocks.pdf "M. Hamburg: Ed448-Goldilocks, a new elliptic curve"
[5]: http://www.ietf.org/rfc/rfc7748.txt "A. Langley, M. Hamburg, and S. Turner: Elliptic Curves for Security.” Internet Engineering Task Force; RFC 7748 (Informational); IETF, Jan-2016"
[6]: https://whispersystems.org/docs/specifications/doubleratchet "Trevor Perrin (editor), Moxie Marlinspike: The Double Ratchet Algorithm"
[7]: https://whispersystems.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet
[8]: https://tools.ietf.org/html/rfc3339
