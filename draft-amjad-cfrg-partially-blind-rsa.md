---
title: "Partially Blind RSA Signatures"
abbrev: "Partially Blind RSA Signatures"
category: info

ipr: trust200902
keyword: Internet-Draft
stand_alone: yes
pi: [toc, sortrefs, symrefs]

docname: draft-amjad-cfrg-partially-blind-rsa-latest
submissiontype: IRTF

author:
 -
    fullname: Your Name Here
    organization: Your Organization Here
    email: "caw@heapingbits.net"

normative:

informative:


--- abstract

This document specifies a blind RSA signature protocol that supports public metadata.
It is an extension to the RSABSSA protocol recently specified by the CFRG.

--- middle

# Introduction

{{?RSABSSA=I-D.irtf-cfrg-rsa-blind-signatures}} specifies the RSA blind
signature protocol, denoted RSABSSA. This is a two-party protocol between
client and server (or signer) where they interact to compute
`sig = Sign(skS, input_msg)`, where `input_msg = Prepare(msg)` is a prepared
version of the private message `msg` provided by the client, and `skS` is
the signing key provided by the server. Upon completion of this protocol,
the server learns nothing, whereas the client learns `sig`. In particular,
this means the server learns nothing of `msg` or `input_msg` and the client
learns nothing of `skS`.

RSABSSA has a variety of applications, with {{?PRIVACY-PASS=I-D.ietf-privacypass-protocol}}
being a canonical example. While useful, this protocol is limited in that
it does not easily accommodate public metadata to be associated with
a (message, signature) pair. In this context, public metadata is information
that's publicly known to both client and server at the time of computation.
This has useful applications in practice. For example, metadata might be used
to encode expiration information for a (message, signature) pair. In practice,
metadata can be encoded using signing key pairs, e.g., by associating one
metadata value with one key pair, but this does not scale well for applications
that have an arbitrary amount of metadata.

This document specifies a variant of RSABSSA that supports public metadata, denoted
RSAPBSSA (RSA Partially Blind Signature with Appendix). Similar to RSABSSA in
{{RSABSSA}}, RSAPBSSSA is defined in such a way that the resulting (unblinded)
signature can be verified with a standard RSA-PSS library.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Notation

The following terms are used throughout this document to describe the protocol operations
in this document:

- bytes_to_int and int_to_bytes: Convert a byte string to and from a non-negative integer.
  bytes_to_int and int_to_bytes are implemented as OS2IP and I2OSP as described in
  {{!RFC8017}}, respectively. Note that these functions operate on byte strings
  in big-endian byte order.
- random_integer_uniform(M, N): Generate a random, uniformly distributed integer R
  between M inclusive and N exclusive, i.e., M <= R < N.
- bit_len(n): Compute the minimum number of bits needed to represent the positive integer n.
- inverse_mod(x, n): Compute the multiplicative inverse of x mod n or fail if x and n are not co-prime.
- is_coprime(x, n): Return true if x and n are co-prime, and false otherwise.
- len(s): The length of a byte string, in bytes.
- random(n): Generate n random bytes using a cryptographically-secure random number generator.
- concat(x0, ..., xN): Concatenation of byte strings. For example,
  concat(0x01, 0x0203, 0x040506) = 0x010203040506.
- slice(x, i, j): Return bytes in the byte string `x` starting from offset `i` and ending at
  offset `j`, inclusive. For example, slice(0x010203040506, 1, 5) = 0x0203040506.
- random_prime(b): Return a random prime number of length b bits.
- is_prime(p): Return true if the input integer p is prime, and false otherwise.

# RSAPBSSA Protocol {#core-protocol}

The RSAPBSSA protocol consists of two helper functions -- AugmentPrivateKey and AugmentPublicKey -- and
four core functions -- Prepare, Blind, BlindSign, and Finalize -- and requires one
round of interaction between client and server. Let `msg` be the client's private input
message, `info` be the public metadata shared between client and server, and `(skS, pkS)`
be the server's private and public key pair. The REQUIRED key generation procedure for RSAPBSSA
is specified in {{key-generation}}.

The protocol begins by the client preparing the message to be signed by computing:

~~~
input_msg = Prepare(msg)
~~~

The client then initiates the blind signature protocol by computing:

~~~
blinded_msg, inv = Blind(pkS, input_msg, info)
~~~

The client then sends `blinded_msg` to the server, which then processes the message
by computing:

~~~
blind_sig = BlindSign(skS, blinded_msg, info)
~~~

The server then sends `blind_sig` to the client, which then finalizes the protocol by computing:

~~~
sig = Finalize(pkS, input_msg, info, blind_sig, inv)
~~~

The output of the protocol is `input_msg` and `sig`. Upon completion, correctness requires that
clients can verify signature `sig` over the prepared message `input_msg` and metadata `metadata`
using the server public key `pkS` by invoking the RSASSA-PSS-VERIFY routine defined in
{{Section 8.1.2 of !RFC8017}}. The Finalize function performs this check before returning the signature.
See {{verification}} for more details about verifying signatures produced through this protocol.

In pictures, the protocol runs as follows:

~~~
   Client(pkS, msg, metadata)          Server(skS, pkS, metadata)
  -------------------------------------------------------
  input_msg = Prepare(msg)
  blinded_msg, inv = Blind(pkS, input_msg, metadata)

                        blinded_msg
                        ---------->

            blind_sig = BlindSign(skS, blinded_msg, metadata)

                         blind_sig
                        <----------

  sig = Finalize(pkS, input_msg, metadata, blind_sig, inv)
~~~

In the remainder of this section, we specify the Blind, BlindSign, and Finalize
functions that are used in this protocol. The Prepare function is as specified in
{{Section 4.1 of RSABSSA}}.

## Key Generation {#key-generation}

The protocol in this document requires signing key pairs to be generated such that
they satisfy a particular criteria. In particular, each RSA modulus for a key pair
MUST be the product of two safe primes p and q. A safe prime p is a prime number
such that p = 2q + 1, where q is also a prime number.

A signing key pair is a tuple (skS, pkS), where each element is as follows:

- skS = (p, q, phi, d), where phi = (p - 1)(q - 1)
- pkS = (n, e), where n = p * q and d * e == 1 mod phi.

The procedure for generating a key pair satisfying this requirement is below.

~~~
KeyGen(bits)

Inputs:
- bits, length in bits of the RSA modulus, a multiple of 2

Outputs:
- (skS, pkS), a signing key pair

Steps:
1. p = SafePrime(bits / 2)
2. q = SafePrime(bits / 2)
3. while p == q, go to step 2.
4. phi = (p - 1) * (q - 1)
5. e = 65537
6. d = inverse_mod(e, phi)
7. skS = (p, q, phi, d)
8. pkS = (p * q, e)
9. output (skS, pkS)
~~~

The procedure for generating a safe prime, denoted SafePrime, is below.

~~~
SafePrime(bits)

Inputs:
- bits, length in bits of the safe prime

Outputs:
- p, a safe prime integer

Steps:
1. q = random_prime(bits - 1)
2. p = (2 * q) + 1
3. if is_prime(p) is True, output p, else go to step 1.
~~~

## Blind {#blind}

The Blind function encodes an input message with the corresponding metadata value and
blinds it with the server's public key. It outputs the blinded message to be sent to
the server, encoded as a byte string, and the corresponding inverse, an integer.
RSAVP1 and EMSA-PSS-ENCODE are as defined in {{Sections 5.2.2 and 9.1.1 of !RFC8017}},
respectively.

If this function fails with an "blinding error" error, implementations SHOULD retry
the function again. The probability of one or more such errors in sequence is negligible.
This function can also fail with an "invalid input" error, which indicates that one of
the inputs (likely the public key) was invalid. Implementations SHOULD update the public
key before calling this function again. See {{errors}} for more information about
dealing with such errors.

Note that this function invokes RSAVP1, which is defined to throw an optional error
for invalid inputs. However, this error cannot occur based on how RSAVP1 is invoked,
so this error is not included in the list of errors for Blind.

~~~
Blind(pkS, msg, metadata)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message
- MGF, the mask generation function
- sLen, the length in bytes of the salt

Inputs:
- pkS, server public key (n, e)
- msg, message to be signed, a byte string
- metadata, public metadata, a byte string

Outputs:
- blinded_msg, a byte string of length kLen
- inv, an integer

Errors:
- "message too long": Raised when the input message is too long (raised by EMSA-PSS-ENCODE).
- "encoding error": Raised when the input message fails encoding (raised by EMSA-PSS-ENCODE).
- "blinding error": Raised when the inverse of r cannot be found.
- "invalid input": Raised when the message is not co-prime with n.

Steps:
1. msg_prime = concat("msg", int_to_bytes(len(metadata), 4), metadata, msg)
2. encoded_msg = EMSA-PSS-ENCODE(msg_prime, bit_len(n))
   with Hash, MGF, and sLen as defined in the parameters
3. If EMSA-PSS-ENCODE raises an error, raise the error and stop
4. m = bytes_to_int(encoded_msg)
5. c = is_coprime(m, n)
6. If c is false, raise an "invalid input" error
   and stop
7. r = random_integer_uniform(1, n)
8. inv = inverse_mod(r, n)
9. If inverse_mod fails, raise an "blinding error" error
   and stop
10. pkM = AugmentPublicKey(pkS, metadata)
11. x = RSAVP1(pkM, r)
12. z = m * x mod n
13. blinded_msg = int_to_bytes(z, kLen)
14. output blinded_msg, inv
~~~

The blinding factor r MUST be randomly chosen from a uniform distribution.
This is typically done via rejection sampling. The function AugmentPublicKey
is defined in {{augment-public-key}}.

## BlindSign

BlindSign performs the RSA private key operation on the client's
blinded message input and returns the output encoded as a byte string.
RSASP1 is as defined in {{Section 5.2.1 of !RFC8017}}.

~~~
BlindSign(skS, blinded_msg, metadata)

Parameters:
- kLen, the length in bytes of the RSA modulus n

Inputs:
- skS, server private key
- blinded_msg, encoded and blinded message to be signed, a
  byte string
- metadata, public metadata, a byte string

Outputs:
- blind_sig, a byte string of length kLen

Errors:
- "signing failure": Raised when the signing operation fails
- "message representative out of range": Raised when the message representative
  to sign is not an integer between 0 and n - 1 (raised by RSASP1)

Steps:
1. m = bytes_to_int(blinded_msg)
2. skM = AugmentPrivateKey(skS, pkS, metadata)
3. pkM = AugmentPublicKey(pkS, metadata)
4. s = RSASP1(skM, m)
5. m' = RSAVP1(pkM, s)
6. If m != m', raise "signing failure" and stop
7. blind_sig = int_to_bytes(s, kLen)
8. output blind_sig
~~~

## Finalize

Finalize validates the server's response, unblinds the message
to produce a signature, verifies it for correctness, and outputs the signature
upon success. Note that this function will internally hash the input message
as is done in Blind.

~~~
Finalize(pkS, msg, metadata, blind_sig, inv)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message
- MGF, the mask generation function
- sLen, the length in bytes of the salt

Inputs:
- pkS, server public key (n, e)
- msg, message to be signed, a byte string
- metadata, public metadata, a byte string
- blind_sig, signed and blinded element, a byte string of
  length kLen
- inv, inverse of the blind, an integer

Outputs:
- sig, a byte string of length kLen

Errors:
- "invalid signature": Raised when the signature is invalid
- "unexpected input size": Raised when a byte string input doesn't
  have the expected length.

Steps:
1. If len(blind_sig) != kLen, raise "unexpected input size" and stop
2. z = bytes_to_int(blind_sig)
3. s = z * inv mod n
4. sig = int_to_bytes(s, kLen)
5. msg_prime = concat("msg", int_to_bytes(len(metadata), 4), metadata, msg)
6. pkM = AugmentPublicKey(pkS, metadata)
7. result = RSASSA-PSS-VERIFY(pkM, msg_prime, sig) with
   Hash, MGF, and sLen as defined in the parameters
8. If result = "valid signature", output sig, else
   raise "invalid signature" and stop
~~~

Note that `pkM` can be computed once during `Blind` and then passed to
`Finalize` directly, rather than being recomputed again.

## Verification

As described in {{core-protocol}}, the output of the protocol is the prepared
message `input_msg` and the signature `sig`. The message that applications
consume is `msg`, from which `input_msg` is derived, along with metadata `metadata`.
Clients verify the signature over `msg` and `info` using the server's public
key `pkS` as follows:

1. Compute `pkM = AugmentPublicKey(pkS, info)`.
2. Compute `msg_prime = concat("msg", int_to_bytes(len(metadata), 4), metadata, msg)`.
3. Invoke and output the result of RSASSA-PSS-VERIFY ({{Section 8.1.2 of !RFC8017}})
   with `(n, e)` as `pkM`, M as `msg_prime`, and `S` as `sig`.

Verification and the message that applications consume therefore depends on
which preparation function is used. In particular, if the PrepareIdentity
function is used, then the application message is `input_msg`.
In contrast, if the PrepareRandomize function is used, then the application
message is `slice(input_msg, 32, len(input_msg))`, i.e., the prepared message
with the random prefix removed.

## Public Key Augmentation {#augment-public-key}

The public key augmentation function (AugmentPublicKey) derives a per-metadata public
key that is used in the core protocol. The hash function used for HKDF is that which
is associated with the RSAPBSSA instance and denoted by the `Hash` parameter. Note that
the input to HKDF is expanded to account for bias in the output distribution.

~~~
AugmentPublicKey(pkS, metadata)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message

Inputs:
- pkS, server public key (n, e)
- metadata, public metadata, a byte string

Outputs:
- pkM, augmented server public key (n, e')

Steps:
1. hkdf_input = concat("key", metadata, 0x00)
2. hkdf_salt = int_to_bytes(n, kLen)
3. lambda_len = kLen / 2
4. hkdf_len = lambda_len + 16
5. expanded_bytes = HKDF(IKM=hkdf_input, salt=hkdf_salt, info="PBRSA", L=hkdf_len)
6. expanded_bytes[0] &= 0x3F // Clear two-most top bits
7. expanded_bytes[lambda_len-1] |= 0x01 // Set bottom-most bit
8. e' = bytes_to_int(slice(expanded_bytes, lambda_len))
9. output pkM = (n, e * e')
~~~

## Private Key Augmentation {#augment-private-key}

The public key augmentation function (AugmentPrivateKey) derives a per-metadata private
signing key that is used by the server in the core protocol.

~~~
AugmentPrivateKey(skS, pkS, metadata)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message

Inputs:
- skS, server private key (p, q, phi, d)
- pkS, server public key (n, e)
- metadata, public metadata, a byte string

Outputs:
- skM, augmented server private key (p, q, phi, d')

Steps:
1. (n, e') = AugmentPublicKey(pkS, metadata)
2. d' = inverse_mod(e', phi)
3. output pkM = (p, q, phi, d')
~~~

# Implementation and Usage Considerations

[[NOTE: we may just want to reference the RSABSSA section for this information]]

This section documents considerations for interfaces to implementations of the protocol
in this document. This includes error handling and API considerations.

## Errors

The high-level functions specified in {{core-protocol}} are all fallible. The explicit errors
generated throughout this specification, along with the conditions that lead to each error,
are listed in the definitions for Blind, BlindSign, and Finalize.
These errors are meant as a guide for implementors. They are not an exhaustive list of all
the errors an implementation might emit. For example, implementations might run out of memory.

Moreover, implementations can handle errors as needed or desired. Where applicable, this document
provides guidance for how to deal with explicit errors that are generated in the protocol. For
example, "blinding error" is generated in Blind when the client produces a prime factor of
the server's public key. {{blind}} indicates that implementations SHOULD
retry the Blind function when this error occurs, but an implementation could also handle this
exceptional event differently, e.g., by informing the server that the key has been factored.

## Signing Key Generation and Usage {#cert-oid}

The RECOMMENDED method for generating the server signing key pair is as specified in FIPS 186-4
{{?DSS=DOI.10.6028/NIST.FIPS.186-4}}.

A server signing key MUST NOT be reused for any other protocol beyond RSAPBSSA. Moreover, a
server signing key MUST NOT be reused for different RSAPBSSA encoding options. That is,
if a server supports two different encoding options, then it MUST have a distinct key
pair for each option.

If the server public key is carried in an X.509 certificate, it MUST use the RSASSA-PSS
OID {{!RFC5756}}. It MUST NOT use the rsaEncryption OID {{?RFC5280}}.

# RSAPBSSA Variants {#rsapbssa}

In this section, we define named variants of RSAPBSSA. These variants consider
different sets of RSASSA-PSS parameters as defined in {{Section 9.1.1 of ?RFC8017}} and explicitly
specified in {{Section 5 of ?RSABSSA=I-D.irtf-cfrg-rsa-blind-signatures}}. For algorithms unique
to RSAPBSSA, the choice of hash function specifies the instantation of HKDF in AugmentPublicKey in
{{augment-public-key}}. The different types of Prepare functions are specified in
{{Section 4.1 of RSABSSA}}.

1. RSAPBSSA-SHA384-PSS-Randomized: This named variant uses SHA-384 as the hash function,
MGF1 with SHA-384 as the PSS mask generation function, a 48-byte salt length, and uses
the randomized preparation function (PrepareRandomize).
2. RSAPBSSA-SHA384-PSSZERO-Randomized: This named variant uses SHA-384 as the hash
function, MGF1 with SHA-384 as the PSS mask generation function, an empty PSS salt, and
uses the randomized preparation function (PrepareRandomize).
3. RSAPBSSA-SHA384-PSS-Deterministic: This named variant uses SHA-384 as the hash function,
MGF1 with SHA-384 as the PSS mask generation function, 48-byte salt length, and uses the
identity preparation function (PrepareIdentity).
4. RSAPBSSA-SHA384-PSSZERO-Deterministic: This named variant uses SHA-384 as the hash
function, MGF1 with SHA-384 as the PSS mask generation function, an empty PSS salt, and
uses the identity preparation function (PrepareIdentity). This is the only variant that
produces deterministic signatures over the client's input message msg.

The RECOMMENDED variants are RSAPBSSA-SHA384-PSS-Randomized or
RSAPBSSA-SHA384-PSSZERO-Randomized.

See {{Section 5 of ?RSABSSA=I-D.irtf-cfrg-rsa-blind-signatures}} for discussion about
interoperability considerations and deterministic signatures.

# Security Considerations

Amjad et al. [[TODO: cite eprint when ready]] proved the following properties of RSAPBSSA:

- One-more-unforgeability: For any adversary interacting with the server (i.e., the signer) as a client
that interacts with the server at most `n` times is unable to output `n+1` valid message and signature
tuples (i.e., the signature verifies for the corresponding message). This holds for any `n` that is polynomial
in the security parameter of the scheme.
- Concurrent one-more-unforgeability: The above holds even in the setting when an adversarial client is interacting
with multiple servers (signers) simultaneously.
- Unlinkability: Consider any adversary acting as the server (signer) interacting with `n` clients using the same
public metadata. Afterwards, the adversary randomly receives one of the `n` resulting signatures as a challenge.
Then, the adversary cannot guess which of the `n` interactions created the challenge signature better than
a random guess.

The first two unforgeability properties rely on the Strong RSA Known Target Inversion Problem. This is
slightly stronger assumption that the RSA Known Target Inversion Problem used in RSABSSA. In the RSA Known
Target Inversion Problem, the challenger is given a fixed public exponent `e` with the goal of computing
the e-th root of `n+1` random elements while using an e-th oracle at most `n` times. In comparison, the
Strong RSA Known Target Inversion Problem enables the challenger to choose any public exponents
`e_1,...,e_n+1 > 1` such that it can be the `e_i`-th root for the `i`-th random element. One can view the
difference between the Strong RSA Known Target Inversion and RSA Known Target Inversion problems identical
to the differences between the Strong RSA and RSA problems.

The final property of unlinkability relies only on the fact that the underlying hash functions are modelled
as random oracles.

All the security considerations of RSABSSA in {{Section 8 of ?RSABSSA=I-D.irtf-cfrg-rsa-blind-signatures}}
also apply to RSAPBSSA here. We present additional security considerations specific to RSAPBSSA below.

## Strong RSA Modulus Key Generation

An essential component of RSAPBSSA is that the KeyGen algorithm in {{key-generation}} generates a RSA
modulus that is the product of two strong primes. This is essential to ensure that the resulting outputs
of AugmentPublicKey in {{augment-public-key}} does cause errors in AugmentPrivateKey in {{augment-private-key}}.
We note that an error in AugmentPrivateKey would incur if the output of AugmentPublicKey does not have an
inverse modulo phi. By choosing the RSA modulus as the product of two strong primes, we guarantee the output of
AugmentPublicKey will never incur errors in AugmentPrivateKey.

It is integral that one uses the KeyGen algorithm for RSAPBSSA instead of the standard RSA key generation algorithms
(such as those used in {{RSABSSA}}). If one uses standard RSA key generation, there are no guarantees provided
for the success of the AugmentPrivateKey function and, thus, being able to correctly sign messages for certain choices
of public metadata.

## Domain Separation for Public Key Augmentation

The purpose of domain separation is to guarantee that the security analysis of any cryptographic protocol remain true
even if multiple instances of the protocol or multiple hash functions in a single instance of the protocol
are instantiated based on one underlying hash function.

The AugmentPublicKey in {{augment-public-key}} of this document already provide domain separation by using the RSA modulus
as input to the underlying HKDF as the info argument. As each instance of RSAPBSSA will have a different RSA modulus, this
effectively ensures that the outputs of the underlying hash functions for multiple instances will be different
even for the same input.

Additionally, the hash function invocation used for computing the message digest is domain separated from the hash function
invocation used for augmenting the public key in AugmentPublicKey. This domain separation is done by prepending the inputs
to each hash function with a unique domain separation tag.

## Choosing Public Metadata

The unlinkability property of RSAPBSSA guarantees anonymity for any signature amongst the set of all interactions with the
server (signer) with the same choice of public metadata. In other words, the server is unable to identify the interaction
that created the signature. The unlinkability guaratee of RSAPBSSA is only useful when there are a significant number of
server (signer) interactions for any value of public metadata. In the extreme case where each server interaction is performed
with a different value of public metadata, then the server can uniquely identify the server interaction that created the
given signature.

Applications that use RSAPBSSA MUST guarantee that the choice of public metadata is limited such that there is a significant
number of server (signer) interactions for any potential value of public metadata.

## Denial of Service 

RSAPBSSA is suspectible to Denial of Service (DoS) attacks due to the flexibility of choosing public metadata used in
AugmentPublicKey in {{augment-public-key}}. In particular, an attacker may try to pick public metadata such that
the output of AugmentPublicKey is very large. As a result, the computational cost of blind signing and verification will
increase leading to suspectibility to DoS attacks.

For applications where the values of potential public metadata choices are fixed ahead of time, it is possible
to try and mitigate DoS attacks. There are only two requirements for the choice of `e'` in AugmentPublicKey in
{{augment-public-key}}. First, `e'` must be smaller than both prime factors of phi. Secondly, the possible values
of `e'` must be large enough to avoid collisions such that two public metadata choices will result in the same `e'`
and, thus, the same augmented public key. During KeyGen in {{key-generation}}, the server (signer) can pick the
smallest length output for the HKDF in AugmentPublicKey such that the output will be different for all relevant
public metadata choices while ensuring augmented public keys are smaller.

# IANA Considerations

This document has no IANA actions.

--- back

# Test Vectors

[[TODO: writeme]]

# Acknowledgments
{:numbered="false"}

[[TODO: writeme]]
