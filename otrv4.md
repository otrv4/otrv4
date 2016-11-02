# OTR version 4

The following messaging protocol provides way for two people to have a conversation over a network
in a way that provides the same security as a private in person conversation, where no external party
can overhear what is being said, and no one (not even the conversation participants) can prove what
was said, or even that the two participants spoke to each other at all.

## Table of Contents

1. [Main Changes over Version 3](#main-changes-over-version-3)
2. [High Level Overview](#high-level-overview)
3. [Assumptions](#assumptions)
4. [Security Properties](#security-properties)
5. [OTR Conversation Initialization](#otr-conversation-initialization)
  1. Version Negotiation
  2. [Deniable Authenticated Key Exchange (DAKE)](#deniable-authenticated-key-exchange-dake)
6. [Requesting conversation with older OTR version](#requesting-conversation-with-older-otr-version)
7. [Data exchange](#data-exchange)
8. Appendices
  1. ROM DRE
  2. ROM Authentication

## Main Changes over Version 3

TODO: Write this section when we have fleshed out the other sections of the spec and decide what is important to highlight here

## High Level Overview

Off The Record messaging (OTR) is a messaging protocol that achieves forward-secrecy
and deniability.

The high level flow of this protocol will be:

    Alice                                            Bob
    --------------------------------------------------------------------------------
    Request OTR conversation          ------------->
                                      <-------------  OTR v4 is supported
    Establish Conversation with DAKE  <------------>  Establish Conversation with DAKE
    Exchange Data Messages            <------------>  Exchange Data Messages

## Assumptions

Both participants are online at the start of a conversation.

Messages in a conversation will be exchanged over an insecure channel, where an attacker can eavesdrop or interfere with the messages.

We assume a network model which provides in-order delivery of messages. Some messages may not be delivered.

## Security Properties

In an off the record conversation, both sides can verify the identity of the other participant
(but cannot transfer this knowledge to a third party). Participants can converse with the assurance
that their conversation will not be read or modified by a hostile third party.

To resemble an in-person conversation means that both ends can deny that they have participated in
said conversation. Both ends can also deny having sent one or many of the exchanged messages in the conversation.

### DAKE properties
 * Mutual authentication
 * Participation repudiation for both initiator and receiver

### Conversation properties
 * Confidentiality
 * Integrity
 * Forward secrecy
 * Message deniability

Threats that an OTR conversation does not mitigate:
* An active attacker may perform a Denial of Service attack but not learn the contents of messages.

## Preliminaries

### Notation

All values on Z_ℓ are MPIs. 

Regarding to elliptic curve operations, we use:

⊕ to represent point additions,  
⊗ to represent scalar multiplications and  
⊖ to represent point subtractions.

### Data types

    Bytes (BYTE):
      1 byte unsigned value

    Shorts (SHORT):
      2 byte unsigned value, big-endian

    Ints (INT):
      4 byte unsigned value, big-endian

    Multi-precision integers (MPI):
      4 byte unsigned len, big-endian
      len byte unsigned value, big-endian
      (MPIs must use the minimum-length encoding; i.e. no leading 0x00 bytes. This is important when calculating public key fingerprints.)

    ED448 points (POINT):
      We need to choose a point serialization format for ed448 points

    Opaque variable-length data (DATA):
      4 byte unsigned len, big-endian
      len byte data


### Public keys and fingerprints

OTR public authentication Cramer-Shoup key (PUBKEY):

    Pubkey type (SHORT)
      Cramer-Shoup public keys have type 0x0010
    
    c (MPI)
    d (MPI)
    h (MPI)
      (c, d, h) are the Cramer-Shoup public key parameters

OTR public keys have fingerprints, which are hex strings that serve as identifiers for the public key. The fingerprint is calculated by taking the SHA-1 hash of the byte-level representation of the public key.

## OTR Conversation Initialization

OTR4 conversations are established by an deniable authenticated key exchange
protocol (DAKE).

There are two ways Alice can inform Bob that she is willing to use the OTR
protocol to speak with him in an interactive setting: by sending him the OTR
Query Message, or by including a special "tag" consisting of whitespace
characters in one of her messages to him. Each method also includes a way for
Alice to communicate to Bob which versions of the OTR protocol she is willing
to speak with him.

The semantics of the interactive OTR Query Message are that Alice is requesting
that Bob start an OTR conversation with her (if he is willing and able to do
so). The semantics of the whitespace tag are that Alice is opportunistically
indicating to Bob that she is willing to have an OTR conversation with him.

For example, if Bob has a policy of "only use OTR when it's explicitly
requested", then he would start an OTR conversation upon receiving an OTR
Query Message, but would not upon receiving the whitespace tag.

Both the OTR Query Message and Whitespace tag include the OTR versions Alice
supports and is willing to use.

Once Bob has decided to start the conversation in response to Alice's request,
he will initiate an interactive, deniable, authenticated key exchange DAKE.

### Version negotiation

OTR4 introduces mandatory version negotiation to resist version rollback. In
both cases, the receiving party will include in the DAKE authenticated
information about what versions they received, and the initializing party will
verify that the versions are correct.

### Deniable Authenticated Key Exchange (DAKE)

This section outlines the flow of the Deniable Authenticated Key Exchange, which
is a way for two parties to mutually agree upon a shared key and authenticate one
another while also allowing a level of participation deniability.

This process is based on the Spawn protocol[1], which utilizes Dual Receiver
Encryption (DRE) and a NIZKPK for authentication (Auth).

Alice long-term Cramer-Shoup key-pair is `SKa = (x1A, x2A, y1A, y2A, zA)` and `PKa = (cA, dA, hA)`.  
Bob long-term Cramer-Shoup key-pair is `SKb = (x1B, x2B, y1B, y2B, zB)` and `PKb = (cB, dB, hB)`.  
Both key pairs are generated with `DRGen()`.  

#### Overview

```
Alice                                          Bob
---------------------------------------------------
Query Message or Whitespace Tag ------->
                                <------- Prekey (ψ1)
                  DRE-Auth (ψ2) ------->
                                         Verify & Decrypt (ψ2)
```

**Alice:**

1. Generates an ephemeral private key `i` from `Z_ℓ` and a public key g1⊗i.
2. Sends Bob ψ1 = ("I", g1⊗i).


**Bob:**

1. Generates an ephemeral private key `r` from `Z_ℓ` and public key g1⊗r.
2. Computes γ = DREnc(PKb, PKa, m), being m = "I" ∥ "R" ∥ g1⊗i ∥ g1⊗r.
3. Computes σ = Auth(hB, zB, {hA, g1⊗i}, "I" ∥ "R" ∥ g1⊗i ∥ γ).
4. Computes k = (g1⊗i) ⊗ r and securely erase `r`.
5. Sends Alice ψ2 = ("R", γ, σ).


**Alice:**

1. Verifies Verif({hA, hB, g1⊗i}, σ, “I” ∥ “R” ∥ g1^i ∥ γ).
2. Decrypts m = DRDec(PKa, PKb, SKa, γ).
3. Verifies the following properties of the decrypted message `m`:
  1. The message is of the correct form (e.g., the fields are of the expected length)
  2. Alice's identifier is the first one listed
  3. Bob's identifier is the second one listed, and it matches the identifier transmitted outside of the ciphertext
4. Computes k = (g1⊗r) ⊗ i and securely erase `i`.


**TODO: the following is about version negotiation and may need to be moved.**

The Query Message or Whitespace Tag will include the versions supported by
Alice.

```
ψ1 = { "B", pubB, g^b, Bobs_versions }
```

"B" is Bob's account identifier. Bobs_versions are the versions supported
by Bob.

```
ψ2 = { "A", pubA, γ, σ } where
γ = DRE(pubB, pubA, "B" || g^b || "A" || g^a)
σ = Auth(hA, zA, {hB, hA, g^b}, "B" || "A" || g^b || Alices_versions || Bobs_versions || γ )
```

"A" is Alice's account identifier.

After receiving ψ2, Alice authenticates σ and decrypts γ. She then verifies the
versions that were sent by both parties. If Bob did not receive the Query
Message or Whitespace Tag sent by Alice or if Bob is using a version of OTR that
is not the highest preferable version, this check will fail. If all checks pass,
then Alice and Bob have a shared secret with which to initialize their data
messages exchange session.

#### Pre-key message

This is the first message of the DAKE. Bob sends it to Alice to commit to a choice of D-H key.

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x01.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For a commit message this will often be 0, since the other party may not have identified their instance tag yet.
Initiator's identifier (DATA)
  This can be the fingerprint or something else.
g1⊗i (MPI)
  - Choose a random value i (446 bits) mod l
  - Encode g1⊗i as the MPI field.
```

#### DRE-Auth message

This is the second message of the DAKE. Alice sends it to Bob to commit to a choice of her D-H key and acknowledgement of Bob's D-H key.
Dual-receiver-encryption is used to encrypt the public key and Zero-knowledge-proof-of-knowledge is used to authenticate the message.

```
Protocol version (SHORT)
  The version number of this protocol is 0x0004.
Message type (BYTE)
  The message has type 0x02.
Sender Instance tag (INT)
  The instance tag of the person sending this message.
Receiver Instance tag (INT)
  The instance tag of the intended recipient. For a commit message this will often be 0, since the other party may not have identified their instance tag yet.
Receiver's identifier (DATA)
  This can be the fingerprint or something else.
γ (DATA)
  - Choose a random value r (446 bits) mod l
  - Compute g1⊗r
  - Generate m = "I" ∥ "R" ∥ g1⊗i ∥ g1⊗r
  - Compute (u11, u21, e1, v1, u12, u22, e2, v2, L, n1, n2, nonce, φ) = DREnc(pubA, pubB, m)
  - Encode each returned value individually and concatenate all of them as γ.
  - Encode the resulting value γ as the DATA field.

  DREnc values are encoded as follows:
  - u11 (POINT)
  - u21 (POINT)
  - e1 (POINT)
  - v1 (POINT)
  - u12 (POINT)
  - u22 (POINT)
  - e2 (POINT)
  - v2 (POINT)
  - L (MPI)
  - n1 (MPI)
  - n2 (MPI)
  - nonce (DATA)
  - φ (DATA)
σ (DATA)
  - Compute (c1, r1, c2, r2, c3, r3) = Auth(hB, zB, {hA, g1⊗i}, "I" ∥ "R" ∥ g1⊗i ∥ γ) 
  - Encode each returned value individually and concatenate all of them as σ.
  - Encode the resulting value σ as the DATA field.
  
  Auth values are encoded as follows:
  - c1 (MPI)
  - r1 (MPI)
  - c2 (MPI)
  - r2 (MPI)
  - c3 (MPI)
  - r3 (MPI)
```

## Requesting conversation with older OTR version

Bob might respond to Alice's request or notify of willingness to start a
conversation with a version lower then version 4. If this is the
case the protocol falls back to [OTR version 3 specification][2].

Note: OTR version 4 is the latest version to support previous versions.

## Data Exchange

This section describes how each participant will use the Double Ratchet
algorithm to exchange data initialized with the shared secret established in the DAKE.

To perform a new ratchet means to rotate the root key and chain key to use a new D-H key pair.
A ratchet represents a group of data messages which are encrypted by keys derived from the
same D-H key pair.

A message with an empty human-readable part (the plaintext is of zero length, or starts
with a NUL) is a "heartbeat" packet, and should not be displayed to the user. (But it's
still useful to effect key rotations.)

```
Alice                                                                           Bob
-----------------------------------------------------------------------------------
Initialize root key, chain keys                        Initialize root key, chain keys
Generate DH, pubDHa, privDHa                           Generate DH, pubDHb, privDHb
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

### Key management

#### For each correspondent, keep track of:

ratchet_flag
i as Current ratchet id
j as Previous sent message id
k as Previous received message id

R as Root key
Cs_j as Sending Chain key
Cr_k as Receiving Chain key
our_dh, their_dh

#### Initialization of Double Ratchet

After the DAKE is finished, both side will initialize the first group of root key (R0) and chain key
(C0_0) deriving from SharedSecret.

How to derive the first ratchet (R0):
```
R0, Ca0_0, Cb0_0 = KDF(SharedSecret)
```

- For the Initiator:
  - Set ratchet_flag as true
  - Set their_dh as g^b from the DAKE
  - She will perform a new ratchet once again when sending her first message
- For the Receiver:
  - Set ratchet_flag as false

Both side will compare their public keys to choose a chain key for sending and receiving:

- Initiator (and similarly for Receiver) determines if she is the "low" end or the "high" end of this Data Message.
If Initiator's ephemeral D-H public key is numerically greater than Receiver's public key, then she is the "high" end.
Otherwise, she is the "low" end.
- Initiator selects the chain keys for sending and receiving:
  - If she is the "high" end, use Ca0_0 as the sending chain key, Cb0_0 as the receiving chain key.
  - If she is the "low" end, use Cb0_0 as the sending chain key, Ca0_0 as the receiving chain key.

#### When you send a Data Message:

1. If ratchet_flag is true, first ratchet:
    1. Derive new pair of R, Cs_0, Cr_0 from private part of our_dh and public part of their_dh.
    2. Securely forget our_dh, increment i, and set our_dh to a new DH key pair which you generate.
    3. Set ratchet_flag to false.

    ```
    our_dh = {pubDHa, privDHa} = generateECDH()

    R1 = SHA3(0x00 || R0 || ECDH(our_dh, their_dh))
    Ca1_0 = SHA3(0x01 || R0 || ECDH(our_dh, their_dh))
    Cb1_0 = SHA3(0x02 || R0 || ECDH(our_dh, their_dh))

    i = i+1
    ratchet_flag = false
    ```

2. Set the ratchet_id to i.
3. Set the DH pubkey in the Data message to the public part of our_dh.
4. Increment j, and use Cs_j to derive the Enc and MAC key.

    ```
    MKenc = SHA3(0x00 || Cs_j)
    MKmac = SHA3(0x01 || Cs_j)
    ```

5. Use the Enc key to encrypt the message, and the MAC key to calculate its mactag.

    ```
    ciphertext = Enc(MKenc, m)
    msg = ciphertext || Mac(MKmac, ciphertext)
    ```

6. Derive the next sending Chain Key

    ```
    Cs_j+1 = SHA3(Cs_j)
    ```

#### When you receive a Data Message:

1. If the ratchet_id is not larger than i, reject the message.
2. If the message_id is not larger than k, reject the message.
3. Use the message_id to compute the Receiving Chain key Cr_message_id.

    ```
    Cr_message_id = SHA3(Cr_message_id-1)
    ```

4. Use the Cr_message_id to derive the Enc and MAC key.

    ```
    MKenc = SHA3(0x00 || Cs_j)
    MKmac = SHA3(0x01 || Cs_j)
    ```

5. Use the MAC key to verify the mactag on the message. If it does not verify, reject the message.

    ```
    ciphertext, mactag = msg
    verify(mactag == Mac(MKmac, m))
    ```

6. Decrypt the message using the Enc key.

    ```
    m = Dec(MKenc, ciphertext)
    ```

7. Set k to message_id, Set ratchet_flag to true, Set their_dh as pubDHRs of the message.

    ```
    k = message_id
    ratchet_flag = true
    ```

### Revealing MAC Keys

We reveal old MAC keys to provide forgeability of messages. Old MAC keys are keys for messages that have already been received, therefore will no longer be used to verify the authenticity of a message.

MAC keys are revealed with data messages. They are also revealed with heartbeat messages (data messages that encode a plaintext of zero length) if the receiver has not sent a message in a configurable amount of time.

A receiver can reveal a MAC key in the following case:

- the receiver has received a message and has verified the message's authenticity
- the receiver has discarded associated message keys
- the receiver has discarded the chain key that can be used to compute the message keys (chain keys from previous ratchets might be stored to compute message keys for skipped or delayed messages)


### Packet format

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

    The bitwise-OR of the flags for this message. Usually you should set this to 0x00. The only currently defined flag is:

    IGNORE_UNREADABLE (0x01)

        If you receive a Data Message with this flag set, and you are unable to decrypt the message or verify
        the MAC (because, for example, you don't have the right keys), just ignore the message instead of producing
        some kind of error or notification to the user.

Ratchet id i (INT)

    Must be strictly greater than 0, and increment by 1 with each ratchet

Message id Ns (INT)

    Must be strictly greater than 0, and increment by 1 with each message

pubDHRs (MPI)

    The *next* ratchet [i.e. sender_keyid+1] public key for the sender

Encrypted message (DATA)

    Using the appropriate encryption key (see below) derived from the sender's and recipient's DH public keys
    (with the keyids given in this message), perform Xsalsa encryption of the message.
    The initial counter is a 16-byte value whose first 8 bytes are the above "top half of counter init" value,
    and whose last 8 bytes are all 0x00.
    Note that counter mode does not change the length of the message, so no message padding needs to be done.
    If you *want* to do message padding (to disguise the length of your message), use the above TLV of type 0.

Authenticator (MAC)

    The SHA3 MAC, using the appropriate MAC key (see below) of everything from the Protocol version to the end
    of the encrypted message

Old MAC keys to be revealed (DATA)

    See "Revealing MAC Keys"
```

## Appendices

### ROM DRE

The DRE scheme consists of three functions: 

`pk, sk = DRGen()`, a key generation function.  
`γ = DREnc(pk1, pk2, m)`, an encryption function.  
`m = DRDec(pk1, pk2, sk_i, γ)`, a decryption function.

#### Domain parameters

The Cramer-Shoup scheme uses a group (G, ℓ, g1, g2). In OTRv4, we choose Ed448 with its group G and its
correspondant prime order ℓ of 446 bits. The generators g1 and g2 are:

g1 = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160)

g2 = (433103962059265674580308903270602732554589039120240665786107503148578357355610867319637982957210103802741854255963765310708419199319826, 637671230437811306883071736319873166937007728586178661428553286712849083212910048075550542694415936278788300723371476615776878488331711)

#### Dual Receiver Key Generation: DRGen()

1. Pick random values x1, x2, y1, y2, z (56 bytes each) in Z_ℓ.
2. Compute group elements c = g1⊗x1 ⊕ g2⊗x2, d = g1⊗y1 ⊕ g2⊗y2, h = g1⊗z. 
3. The public key is pk = {c, d, h} and the secret key is sk = {x1, x2, y1, y2, z}.


#### Dual Receiver Encryption: DREnc(pk_1, pk_2, m)

1. Pick random values K, k_1, k_2 (56 bytes each) in Z_ℓ.
2. For i ∈ {1,2}:
  1. pk_i = {c_i,d_i,h_i}
  2. Compute u_1i = g1⊗k_i, u_2i = g2⊗k_i, e_i = (h_i⊗k_i) ⊗ K
  3. Compute α_i = MapToZl(u_1i ∥ u_2i ∥ e_i).
  4. Compute v_i = (c_i⊗k_i) ⊕ (d_i⊗(k_i ⊗ α_i))
3. Compute K_enc = SHA3-256(K).
4. Pick a random 24 bytes nonce and compute φ = XSalsa20-Poly1305_K_enc(m, nonce)
5. Generate a NIZKPK: 
  1. for i ∈ {1,2}: 
    1. Pick random value t_i (56 bytes) in Z_ℓ. 
    2. Compute T_1i = g1⊗t_i, T_2i = g2⊗t_i, T_3i = (c_i ⊕ (d_i⊗α_i))⊗t_i. 
  2. Compute T_4 = (h_1⊗t_1) ⊖ (h_2⊗t_2).
  3. Compute L = MapToZl(g1 ∥g2 ∥ ℓ ∥ pk_1 ∥ pk_2 ∥ u_11 ∥ u_21 ∥ e_1 ∥ v_1 ∥ α_1 ∥ u_12 ∥ u_22 ∥ e_2 ∥ v_2 ∥ α_2 ∥ T_11 ∥ T_21 ∥ T_31 ∥ T_12 ∥ T_22 ∥ T_32 ∥ T_4 ).
  4. Generate for i ∈ {1,2}: 
    1. Compute n_i = t_i - L * k_i (mod ℓ).
6. Send γ = (u_11, u_21, e_1, v_1, u_12, u_22, e_2, v_2, L, n_1, n_2, nonce, φ).


#### Dual Receiver Decryption: DRDec(pk_1, pk_2, sk_i, γ):

1. Parse γ to retrieve components γ = (u_11, u_21, e_1, v_1, u_12, u_22, e_2, v_2, L, n_1, n_2, nonce, φ).
2. Verify NIZKPKi: 
  1. for j ∈ {1,2} compute:
    1. α'_j = MapToZl(u1_j ∥ u_2j ∥ e_j)
    2. T'_1j = (g1⊗n_j) ⊕ (u_1j⊗L)
    3. T'_2j = (g2⊗n_j) ⊕ (u_2j⊗L)
    4. T'_3j = (c_j ⊕ (d_j⊗a'_j))⊗n_j ⊕ (v_j⊗L)
  2. T'_4 = ((h1⊗n1) ⊖ (h2⊗n2)) ⊕ ((e1 ⊖ e2)⊗L)
  3. Compute L' = MapToZl(g1 ∥ g2 ∥ q ∥ pk_1 ∥ pk_2 ∥ u_11 ∥ u_21 ∥ e_1 ∥ v_1 ∥ α'_1 ∥ u_12 ∥ u_22 ∥ e_2 ∥ v_2 ∥ α'_2 ∥ T'_11 ∥ T'_21 ∥ T'_31 ∥ T'_12 ∥ T'_22 ∥ T'_32 ∥ T'_4 ).
  4. Verify L ≟ L.
  5. Compute t_1 = u_1i⊗x_1i, t2 = u_2i⊗x_2i, t3 = u_1i⊗y_1i, t4 = u_2i⊗y_2i
  6. Verify t_1 ⊕ t2 ⊕ (t3 ⊕ t4)⊗α'_i ≟ v_i.
3. Recover secret key K_enc = (e_i) ⊖ (u1_i⊗z_i).
4. Decrypt m = XSalsa20-Poly1305_K_enc(φ, nonce).


### ROM Authentication

The Authentication scheme consists of two functions:

`σ = Auth(A_2, a_2, {A_1, A_3}, m)`, an authentication function.  
`Verif({A_1, A_2, A_3}, σ, m)`, a verification function.

#### Domain parameters

We reuse the previously defined generator in Cramer-Shoup of DRE:

g = (501459341212218748317573362239202803024229898883658122912772232650473550786782902904842340270909267251001424253087988710625934010181862, 44731490761556280255905446185238890493953420277155459539681908020022814852045473906622513423589000065035233481733743985973099897904160).

#### Authentication: Auth(A2, a_2, {A_1, A_3}, m):

A_2 is the public value associated with a_2, that is, `A_2 = g⊗a_2`.  
m is the message to authenticate.

1. Pick random values t_1, c_2, c_3, r_2, r_3 (56 bytes each) in Z_ℓ.
2. Compute T_1 = g⊗t_1.
3. Compute T_2 = (g⊗r_2) ⊕ (A_2⊗c_2).
4. Compute T_3 = (g⊗r_3) ⊕ (A_3⊗c_3).
5. Compute c = MapToZl(g ∥ ℓ ∥ A_1 ∥ A_2 ∥ A_3 ∥ T_1 ∥ T_2 ∥ T_3 ∥ m).
6. Compute c_1 = c - c_2 - c_3 (mod ℓ).
7. Compute r_1 = t_1 - c_1 * a_2 (mod ℓ). 
8. Send σ = (c_1, r_1, c_2, r_2, c_3, r_3).

#### Verification: Verif({A_1, A_2, A_3}, σ, m)

1. Parse σ to retrive components (c_1, r_1, c_2, r_2, c_3, r_3).
2. Compute T1 = (g⊗r_1) ⊕ (A_1⊗c_1)
3. Compute T2 = (g⊗r_2) ⊕ (A_2⊗c_2)
4. Compute T3 = (g⊗r_3) ⊕ (A_3⊗c_3)
5. Compute c' = MapToZl(g ∥ ℓ ∥ A_1 ∥ A_2 ∥ A_3 ∥ T1 ∥ T2 ∥ T3 ∥ m).
6. Check if c' ≟ c_1 + c_2 + c_3 (mod ℓ).

### MapToZl(d)

d is an array of bytes.

1. Compute h = SHA3-512(d) as an unsigned value, big-endian.
2. Return h mod ℓ

## References

1. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf  
2. https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
