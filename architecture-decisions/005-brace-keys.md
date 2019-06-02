## ADR 5: Brace key

### Context

It is acknowledged that there may be unknown weaknesses in elliptic curve
cryptography and that quantum computers may arrive earlier than predicted.

For this reason, we propose an additional mechanism for protecting transcripts
against post-conversation decryption.

OTRv4 does not take advantage of quantum resistant algorithms, as the key
described here does not provide any kind of post-quantum confidentiality.
When fault-tolerant quantum computers break Ed448-Goldilocks keys, it will take
some years beyond that point to break the described 3072-bit Diffie-Hellman
keys.

### Proposal

We believe we can protect transcripts from post-conversation decryption by
mixing another key obtained from a Diffie-Hellman (DH) exchange into the key
material. This additional key is called the “brace key”.

This document specifies:

1. The brace key to mix in with the ECDH shared secret when deriving a new
   Mixed shared secret.
2. An algorithm for ratcheting and deriving the brace key.

This document only changes the way root keys are derived during the Double
Ratchet algorithm.

The first 3072-bit DH key agreement takes place in the DAKE, as a traditional
Diffie-Hellman key exchange.

We considered two options for ratcheting/deriving the brace key:

1. Obtain a brace key from a DH function which requires the other party to
   contribute to the computation each time a new Mixed shared secret is derived.
2. Obtain a brace key with DH functions which require the other party to
   contribute to the computation every n times. Between these derivations, the
   brace keys are obtained using a key derivation function (KDF) that is seeded
   with the last DH key. For 'n' we propose 'n = 3'.

We chose the second option. Therefore, OTRv4 uses 'n = 3'.

### Algorithm

**k_dh = A_i, a_i**

A brace key is a key that is added to the KDF used to derive a new Mixed shared
secret. A brace key can be produced through a DH function or through a key
derivation function. The first method produces a 3072-bit public key which is
later used as an input to a key derivation
function `KDF(usage_third_brace_key || k_dh, 32)`.

The second method produces a 32-byte key as a result of a key derivation
function that takes as an input the previous brace key
`KDF(usage_brace_key || brace_key, 32)`.

This key has a 128-bit security level  according to Table 2: Comparable
strengths in NIST’s Recommendation for Key Management,
page 53 [\[1\]](#references).

**generateDH function: generateDH()**

Generates `A_i` and `a_i`.

**DH function: DH(a_i, B_i)**

Given `a_i`, a secret key, and `B_i`, a public key, generates a shared secret
value: `k_dh`.

**Key Derivation Function: SHAKE-256(k_dh)**

Given a 3072-bit shared secret value `k_dh`, the SHAKE-256 generates a 32-byte
digest: `brace_key`.

**Key Derivation Function: SHAKE-256(brace_key)**

Given `brace_key`, the SHAKE-256 generates a 32-byte digest: a new `brace_key`.

#### Considerations

Deriving the 3072-bit DH public key will increase the time it takes to
exchange messages. To mitigate this, the key won’t be generated every time
chain keys are derived. Instead, this key will be computed with a DH
function every third DH ratchet and the interim keys will be derived from the
previous `brace_key`. After generating new DH keys, the new public key will be
sent in every message of that ratchet in order to allow transmission even if one
of the messages is dropped.

The brace key will be mixed with the ECDH key to produce the Mixed shared
secret.

#### Implementation

Alice's DH keypair = `(a_i, A_i)`

Bob's DH keypair = `(b_i, B_i)`

Every Mixed shared secret derivation requires both an ECDH key and a brace key.
For the purposes of this explanation, we will only discuss the brace key.

`n` is the number of DH ratchets before performing a new DH computation. This
variable is set to 3.

The interim root key derivations will use a brace key derived from a
`SHAKE-256` using the previous brace key as the seed.

*When n is configured to equal 3*

```
If we assume messages have been sent by Alice and Bob after the DAKE and we are
now at a DH ratchet #3:

Alice                                                 Bob
---------------------------------------------------------------------------------------------
* Generates a new public DH key 'A_1' and
  a secret key 'a_1'
* Derives a new DH shared secret using Bob's
  public key received in a previous ratchet ('B_0')
    'k_dh = DH(B_0, a_1)'
* Derives the new brace key from 'k_dh'
    brace_key_3 = KDF(usage_brace_key || k_dh, 32)
* Mixes the brace key with the ECDH shared
  secret to create the Mixed shared secret 'K_3'
    'K_3 =
    KDF(usage_shared_secret || K_ecdh || brace_key_3, 64)'
* Generates the root key and
  the sending chain key from root key 2 ('root_key_2')
  and the Mixed shared secret ('K_3')
    'root_key_3 = KDF(usage_root_key || root_key_2 || K_3, 64)'
    'chain_key_s_0 = KDF(usage_chain_key || root_key_2 || K_3, 64)'
* Encrypts data message with a message key
  derived from 'chain_key_s_0'
* Sends data_message_0 attached with 'A_1' ----------------->
                                                     * Generates a new public DH key 'B_1' and secret
                                                       key 'b_1'
                                                     * Derives a new DH shared secret using Alice's
                                                       public key received in the data message ('A_1')
                                                         'k_dh = DH(A_1, b_1)'
                                                     * Derives the new brace key from the 'k_dh'
                                                         'brace_key_3 = KDF(usage_brace_key || k_dh, 32)'
                                                     * Mixes the brace key with the ECDH shared secret
                                                       to create the shared secret 'K_3'
                                                         'K_3 = KDF(usage_shared_secret || K_ecdh || brace_key_3, 64)'
                                                     * Generates the root and the receiving chain key
                                                       from root key 2 ('root_key_2') and from the
                                                       Mixed shared secret ('K_3')
                                                        'root_key_3 = KDF(usage_root_key || root_key_2 ||
                                                         K_3, 64)'
                                                        'chain_key_r_0 = KDF(usage_chain_key || root_key_2 ||
                                                         K_3, 64)'
                                                     * Decrypts the received message with a message key
                                                       derived from 'chain_key_r_0'
                                                     * Derives a new brace key from the one derived
                                                       previously
                                                         'brace_key_4 = KDF(usage_brace_key || brace_key, 32)'
                                                     * Generates new ECDH keys and uses Alice's ECDH
                                                       public key (received in data_message_0) to
                                                       create the ECDH shared secret ('K_ecdh').
                                                     * Mixes the brace key with 'K_ecdh' to create
                                                       the Mixed shared secret 'K_4'
                                                         'K_4 = KDF(usage_shared_secret || K_ecdh ||
                                                          brace_key_4, 64)'
                                                     * Generates the root and the sending chain key
                                                       from root key 3 ('root_key_3') and from the
                                                       Mixed shared secret ('K_4')
                                                         'root_key_4 = KDF(usage_root_key || root_key_3 ||
                                                          K_4, 64)'
                                                         'chain_key_s_0 = KDF(usage_chain_key || root_key_3 ||
                                                          K_4, 64)'
                                                      * Encrypts data message with a message key derived
                                                        from 'chain_key_s_0'
                                  <-----------------  * Sends data_message_0
```

**Alice or Bob sends the first message in a DH ratchet (a first reply)**

A new DH ratchet happens every time you:

1. Send a data message after receiving one from the other side
2. When you receive a data message that advertises a new ECDH public key from
   the other party.

The state variable `i` exists to keep track of the last time a DH key was
generated. It is increased every time a DH ratchet happens.

If `i %  3 == 0`

  * Compute the new brace key from a DH computation e.g.
    `brace_key_i = KDF(usage_third_brace_key || DH(our_DH.secret, their_DH.public), 32)`.
  * Send the new `brace_key`'s public key (our_DH.public) to the other party
    for further key computation.

Otherwise

  * Derive the new brace key:
    `KDF(usage_brace_key || brace_key, 32)`

**Alice or Bob send a follow-up message**

When a new public key has been generated and sent in the first message in a
ratchet, all follow up messages in that DH ratchet will also need to advertise
the DH public key in case they arrive in an out-of-order way or they are dropped.

**Alice or Bob receive the first message in a ratchet**

If `i %  3 == 0`:

   * Check that a new DH public key is attached to the message.

    * If it is not:
      * Reject the message.

    * Otherwise:
      * Compute the new brace key from a new DH computation e.g.
        `brace_key_i = KDF(usage_third_brace_key || DH(our_DH.secret, their_DH.public), 32)
      * Use `brace_key_i` to calculate the Mixed shared secret.

**Diagram: Pattern of DH computations and key derivations in a conversation**

This diagram describes when public keys should be sent and when Alice and Bob
should compute the `brace_key` from a KDF or a new DH computation.

Both parties share knowledge of `brace_key_0`, established immediately after
the DAKE.

Given

    Alice's DH keypair = (a_i, A_i)
    Bob's DH keypair = (b_i, B_i)

If Alice sends the first message:

```
    Alice                 ratchet_id        public_key           Bob
---------------------------------------------------------------------------------------

brace_key_1 = KDF(brace_key_0)   -----1---------------->   brace_key_1 = KDF(brace_key_0)
brace_key_2 = KDF(brace_key_1)   <----2-----------------   brace_key_2 = KDF(brace_key_1)
brace_key_3 = KDF(DH(a_1, B_0))  -----3-------A_1------>   brace_key_3 = KDF(DH(b_0, A_1))
brace_key_4 = KDF(brace_key_3)   <----4-----------------   brace_key_4 = KDF(brace_key_3)
brace_key_5 = KDF(brace_key_4)   -----5---------------->   brace_key_5 = KDF(brace_key_4)
brace_key_6 = KDF(DH(a_1, B_1))  <----6-------B_1-------   brace_key_6 = KDF(DH(b_1, A_1))
brace_key_7 = KDF(brace_key_6)   -----7---------------->   brace_key_7 = KDF(brace_key_6)
brace_key_8 = KDF(brace_key_7)   <----8-----------------   brace_key_8 = KDF(brace_key_7)
brace_key_9 = KDF(DH(a_2, B_1))  -----9-------A_2------>   brace_key_9 = KDF(DH(b_1, A_2))
```

### Performance

Computation of `g^a`, `g^b` and `g^a^b` takes under a second when using the
generator `g = 2`. Exponents `a` and `b` are 3072 bits long in an Intel Core
i7 2.2GHz.

| Operation           | Repeat times | Time per Operation |
| ------------------- | ------------ | ------------------ |
| ComputeSharedSecret | 2000         | 22.198064 ms/op    |
| KeyGeneration       | 1000         | 31.607442 ms/op    |

### Decision

We've decide to use a 3072-bit key produced by:

1. a DH function which takes as an argument the other party’s exponent
   (advertised through a data message) to produce brace key.
2. a KDF `KDF(usage_brace_key || brace_key, 32)` which uses the previous brace
   key to produce a new one.

The DH function will run every `n = 3` times because:

1. It is a small number so a particular key can only be compromised for a
   maximum of n ratchets. This means that the maximum ratchets that will
   use the brace key or a key derived from the brace key is 3 (from the sender
   and from the receiver side).

The group used for this key is the one assigned with id 15 in the IETF paper,
RFC 3526 [\[2\]](#references):

* Prime is:
  2^3072 - 2^3008 - 1 + 2^64 * (integer_part_of(2^2942 * π) + 1690314)
* Hex value:

  ```
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
  ```

* Generator g3: 2

### Consequences

Using a 3072-bit DH function to produce the brace key increases the size of data
messages by 32 bytes of extra key material. The increased size may cause some
transport protocols to fragment these messages.

### References

1. Barker, E. (2016). *Recommendation for Key Management*, NIST Special
   Publication 800-57. Available at:
   http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
2. Kojo, M. (2003). *More Modular Exponential (MODP) Diffie-Hellman groups for
   Internet Key Exchange (IKE)*, Internet Engineering Task Force,
   RFC 3526. Available at: https://www.ietf.org/rfc/rfc3526.txt