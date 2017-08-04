## ADR 5: Mix Keys

### Context

We acknowledge that there may be potential weaknesses in elliptic curves and
that quantum computers may arrive earlier than we predict.

We propose an additional mechanism for protecting transcripts against post-
conversation decryption.

### Proposal

We believe we can protect transcripts from post-conversation decryption by
mixing another key obtained from a Diffie-Hellman (DH) exchange into the key
material. This additional key is called the “mix key”.

This proposal specifies:

1. The extra key to mix in with the ECDH shared secret when deriving a new
   root key.
2. An algorithm for ratcheting and deriving the mix key.

This proposal only changes how root keys are derived in the Double Ratchet algorithm.

The first 3072-bit DH key agreement takes place in the DAKE. See Nik Unger's
paper [\[1\]](#references), which specifies DAKEZ, ZDH, and XZDH as (optionally)
quantum-resistant key exchanges.

We are trying to protect against elliptic curve weaknesses, and SIDH
[\[2\]](#references) is specific for post-quantum resistance. Instead, we'll use
a classic DH key exchange.

We considered two options for ratcheting/rederiving the mix key:

1. Obtain a mix key from a DH function which requires the other party to
   contribute to the computation each time a new root key is derived.
2. Obtain a mix key with DH functions which require the other party to
   contribute to the computation every n times. Between these derivations,
   the mix keys are obtained using a key derivation function (KDF) that is
   seeded with the last DH key. We propose n = 3, but n can be adjusted for
   performance.

We chose the second option.

### Algorithm

In this description of the algorithm's functions, we will assume n = 3.

**k_dh = A_i, a_i**

A mix key is a key that is added to the KDF used to produce new root and chain
keys. A mix key can be produced through a DH function and through a key
derivation function, both of which produce a 3072-bit public key. This key has a
128-bit security level according to Table 2: Comparable strengths in NIST’s
Recommendation for Key Management, page 53 [\[3\]](#references).

**generateDH function: generateDH()**

Generates `A_i` and `a_i`.

**DH function: DH(a_i, B_i)**

Given `a_i`, a secret key, and `B_i`, a public key, generates a shared secret value: `k_dh`.

**Key Derivation Function: SHA3-256(k_dh)**

Given a 3072-bit shared secret value `k_dh`, the SHA3-256 generates a 256-bit
digest: `mix_key`.

**Key Derivation Function: SHA3-256(mix_key)**

Given `mix_key`, the SHA3-256 generates a 256-bit digest: a new `mix_key`.

#### Considerations

Transmitting the 3072-bit DH public key will increase the time it takes to
exchange messages. To mitigate this, the key won’t be transmitted every time the
root and chain keys are derived. Instead, this key will be computed with a DH
function every third time and the interim keys will be derived from the
previous `mix_key`. After generating new DH keys, the new public key will be
sent in every message of that ratchet in order to allow transmission even if
one of the messages is dropped.

The mix key will be mixed in at the root level with the ECDH key.

#### Implementation

Alice's DH keypair = `(a_i, A_i)`

Bob's DH keypair = `(b_i, B_i)`

`mix_key` = in this document, it will be referred to as `M_i` for ease.

Every root key derivation requires both an ECDH key and a mix key. For the
purposes of this explanation, we will only discuss the mix key.

`n` is the number of root key derivations before performing a new DH
computation.

The interim root key derivations will use a mix key derived from a SHA3-256
using the previous mix key as the seed.

_When n is configured to equal 3_

```
If we assume messages have been sent by Alice and Bob after the DAKE and we are
now at ratchet 3:

Alice                                                Bob
-----------------------------------------------------------------------------------------
* Increases ratchet_id by one
* Generates new public DH key A_1 and
  secret key a_1
* Derives a new DH shared secret using Bob's
  public key received during the DAKE (B_0)
    k_dh = DH(B_0, a_1)
* Derives the new mix key from the k_dh
    M_3 = SHA3-256(k_dh)
* Mixes the mix key with the ECDH shared
  secret to create the shared secret K_3
    K_3 = SHA3-512(ECDH_3 || M_3)
* Uses K_3 with SHA3-512 to generate root
  and chain keys
    R_3, Cs_3_0, Cr_3_0 = SHA3-512(R_2, K_3)
* Encrypts data message with a message key
  derived from Cs_3_0
* Sends data_message_3_0 with A_1 ----------------->
                                                     * Generates new public DH key B_1 and
                                                       secret key b_1
                                                     * Derives a new DH shared secret using Alice's
                                                       public key received in the message (A_1)
                                                         k_dh = DH(A_1, b_1)
                                                     * Derives the new mix key from the k_dh
                                                         M_3 = SHA3-256(k_dh)
                                                     * Mixes the mix key with the ECDH shared secret
                                                       to create the shared secret K_3
                                                         K_3 = SHA3-512(ECDH_3 || M_3)
                                                     * Uses K_3 with SHA3 to generate root
                                                       and chain keys
                                                         R_3, Cs_3_0, Cr_3_0 = KDF(R_2 || K_3)
                                                     * Decrypts received message with a message key
                                                       derived from Cr_3_0
                                                     * Increases ratchet_id by one
                                                     * Derives a new mix key from the one
                                                       derived in the previous ratchet
                                                         M_4 = KDF(M_3)
                                                     * Generates new ECDH keys and uses Alice's ECDH
                                                       public key (received in
                                                                       data_message_3_0) to create ECDH
                                                       shared secret (ECDH_4).
                                                     * Mixes the mix key with ECDH_4 to create the shared
                                                       secret K_4
                                                          K_4 = SHA3-512(ECDH_4 || M_4)
                                                      * Uses K_4 with SHA3-512 to generate root and chain
                                                        keys from root key 3 (R_3)
                                                           R_4, Cs_4_0, Cr_4_0 = SHA3-512(R_3, K_4)
                                                      * Encrypts data message with a message key derived
                                                        from Cr_4_0
                                <-------------------  * Sends data_message_4_0
```

**Alice or Bob sends the first message in a ratchet (a first reply)**

The ratchet identifier `ratchet_id` increases every time a greater `ratchet_id` is
received or a new message is being sent and signals the machine to ratchet, i.e.
`ratchet_id += 1`

If `ratchet_id % 3 == 0 && sending the first message of a new ratchet`

  * Compute the new mix key from a new DH computation e.g. `M_i =
        SHA3-256(DH(our_DH.secret, their_DH.public))`
  * Send the new `mix_key`'s public key (our_DH.public) to the other party for further key computation.

Otherwise

  * Compute the new mix key `M_i = SHA3-256(M_(i-1))`

**Alice or Bob send a follow-up message**

When a new public key has been generated and sent in the first message in a
ratchet, all follow up messages in that ratchet will also need the public key to
ensure that the other party receives it.

If `ratchet_id % 6 == 3 || ratchet_id % 6 == 0`

   * Send public key

**Alice or Bob receive the first message in a ratchet**

The ratchet_id will need to be increased, so `ratchet_id += 1`

If `ratchet_id % 6 == 3 || ratchet_id % 6 == 0`

   * A new public key should be attached to the message. If it is not, reject the
     message.

Otherwise:

   * Compute the new mix key from a new DH computation e.g.
        `M_i = SHA3-256(DH(our_DH.secret, their_DH.public))`
   * Use `M_i` to decrypt the received message.

**Alice or Bob receive a follow up message**

If the `ratchet_id` is not greater than the current state of `ratchet_id`, then
this is not a new ratchet. In this case there is no further action to be taken for
the mix key.

**Diagram: Pattern of DH computations and key derivations in a conversation**

This diagram describes when public keys should be sent and when Alice
and Bob should compute the `mix_key` from a SHA3 or a new DH computation.

Both parties share knowledge of `M_0`, which is a `mix_key` established in
the DAKE.

Given

    Alice's DH keypair = (a_i, A_i)
    Bob's DH keypair = (b_i, B_i)

If Alice sends the first message:

```
    Alice                 ratchet_id        public_key           Bob
---------------------------------------------------------------------------------------

M_1 = SHA3(M_0)            -----1----------------------->     M_1 = SHA3(M_0)
M_2 = SHA3(M_1)            <----2------------------------     M_2 = SHA3(M_1)
M_3 = SHA3(DH(a_1, B_0))   -----3--------------A_1------>     M_3 = SHA3(DH(b_0, A_1))
M_4 = SHA3(M_3)            <----4------------------------     M_4 = SHA3(M_3)
M_5 = SHA3(M_4)            -----5----------------------->     M_5 = SHA3(M_4)
M_6 = SHA3(DH(a_1, B_1))   <----6--------------B_1-------     M_6 = SHA3(DH(b_1, A_1))
M_7 = SHA3(M_6)            -----7----------------------->     M_7 = SHA3(M_6)
M_8 = SHA3(M_7)            <----8------------------------     M_8 = SHA3(M_7)
M_9 = SHA3(DH(a_2, B_1))   -----9--------------A_2------>     M_9 = SHA3(DH(b_1, A_2))
```

### Performance

Computation of g^a, g^b and g^a^b takes under a second using generator
g = 2. Exponents `a` and `b` are 3072 bits long in an Intel Core i7
2.2GHz.

| Operation           | Repeat times | Time per Operation |
| ------------------- | ------------ | ------------------ |
| ComputeSharedSecret | 2000         | 22.198064 ms/op    |
| KeyGeneration       | 1000         | 31.607442 ms/op    |

### Decision

We’ve decide to use a 3072-bit key produced by:

1. a DH function which takes as an argument the other party’s exponent through a data
   message to produce mix key.
2. a KDF (SHA3-256) which uses the previous mix key to produce a new one.

The DH function will run every n = 3 times because:

1. It is a small number so a particular key can only be compromised for a maximum
   of 2 \* n ratchets. This means that the maximum ratchets that will use the mix
   key or a key derived from the mix key is 6.
2. The benefit of using an odd number is for simplicity of implementation. With an
   odd number, both Alice and Bob can generate a new public and secret key at the
   same time as sending the public key and compute a new mix key from a DH
   function. However, with an even number, Alice would need to generate and send a
   key in a different ratchet to the one where the public key would be used. This
   happens because the public key would only be used in a mix key computed from a
   new DH function on even numbers of ratchet_ids so only Bob would be the sender
   at these times.

From the IETF paper, RFC 3526 [\[4\]](#references):

* Prime is: 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }
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
* The public keys should be 448 bits (56 bytes) long.

### Consequences

Using a 3072-bit DH function to produce the mix key increases the size of data
messages by 56 bytes. of extra key material. The increased size may cause some
transport protocols to fragment these messages.

### References

1. http://cacr.uwaterloo.ca/techreports/2016/cacr2016-06.pdf "N. Unger, I. Goldberg: Improved Techniques for Implementing Strongly Deniable Authenticated Key Exchanges"
2. https://eprint.iacr.org/2011/506.pdf "L. de Feo, D. Jao, J. Plût: Towards Quantum-Resistant Cryptosystems from Supersingular Elliptic Curve Isogenies"
3. http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf "E. Barker: NIST Special Publication 800-57 Part 1 Revision 4; Recommendation for Key Management; Part 1 General"
4. https://www.ietf.org/rfc/rfc3526.txt "M. Kojo: More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)"
