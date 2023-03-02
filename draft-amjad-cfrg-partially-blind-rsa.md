---
title: "Partially Blind RSA Signatures"
abbrev: "Partially Blind RSA Signatures"
category: info

ipr: trust200902
keyword: Internet-Draft

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
clients can verify signature `sig` over the prepared message `input_msg` and metadata `info`
using the server public key `pkS` by invoking the RSASSA-PSS-VERIFY routine defined in
{{Section 8.1.2 of !RFC8017}}. The Finalize function performs this check before returning the signature.
See {{verification}} for more details about verifying signatures produced through this protocol.

In pictures, the protocol runs as follows:

~~~
   Client(pkS, msg, info)          Server(skS, pkS, info)
  -------------------------------------------------------
  input_msg = Prepare(msg)
  blinded_msg, inv = Blind(pkS, input_msg, info)

                        blinded_msg
                        ---------->

            blind_sig = BlindSign(skS, blinded_msg, info)

                         blind_sig
                        <----------

  sig = Finalize(pkS, input_msg, info, blind_sig, inv)
~~~

In the remainder of this section, we specify the Blind, BlindSign, and Finalize
functions that are used in this protocol. The Prepare function is as specified in
{{Section 4.1 of RSABSSA}}.

## Key Generation {#key-generation}

[[TODO: describe how to generate the strong RSA key pair]]

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
Blind(pkS, msg, info)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message
- MGF, the mask generation function
- sLen, the length in bytes of the salt

Inputs:
- pkS, server public key (n, e)
- msg, message to be signed, a byte string
- info, public metadata, a byte string

Outputs:
- blinded_msg, a byte string of length kLen
- inv, an integer

Errors:
- "message too long": Raised when the input message is too long (raised by EMSA-PSS-ENCODE).
- "encoding error": Raised when the input message fails encoding (raised by EMSA-PSS-ENCODE).
- "blinding error": Raised when the inverse of r cannot be found.
- "invalid input": Raised when the message is not co-prime with n.

Steps:
1. msg_prime = concat(msg, metadata)
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
10. pkM = AugmentPublicKey(pkS, info)
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
BlindSign(skS, blinded_msg, info)

Parameters:
- kLen, the length in bytes of the RSA modulus n

Inputs:
- skS, server private key
- blinded_msg, encoded and blinded message to be signed, a
  byte string
- info, public metadata, a byte string

Outputs:
- blind_sig, a byte string of length kLen

Errors:
- "signing failure": Raised when the signing operation fails
- "message representative out of range": Raised when the message representative
  to sign is not an integer between 0 and n - 1 (raised by RSASP1)

Steps:
1. m = bytes_to_int(blinded_msg)
2. skM = AugmentPrivateKey(skS, pkS, info)
3. pkM = AugmentPublicKey(pkS, info)
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
Finalize(pkS, msg, info, blind_sig, inv)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message
- MGF, the mask generation function
- sLen, the length in bytes of the salt

Inputs:
- pkS, server public key (n, e)
- msg, message to be signed, a byte string
- info, public metadata, a byte string
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
5. msg_prime = concat(msg, info)
6. pkM = AugmentPublicKey(pkS, info)
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
consume is `msg`, from which `input_msg` is derived, along with metadata `info`.
Clients verify the signature over `msg` and `info` using the server's public
key `pkS` as follows:

1. Compute `pkM = AugmentPublicKey(pkS, info)`.
2. Compute `msg_prime = concat(input_msg, info)`.
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
key that is used in the core protocol.

~~~
AugmentPublicKey(pkS, info)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message

Inputs:
- pkS, server public key (n, e)
- info, public metadata, a byte string

Outputs:
- pkM, augmented server public key (n, e')

Steps:
1. hkdf_salt = concat(info, 0x00)
2. hkdf_info = int_to_bytes(n, kLen)
3. lambda_len = kLen / 2
3. hkdf_len = lambda_len + 16
4. expanded_bytes = HKDF(IKM=hkdf_salt, info=hkdf_info, L=hkdf_len)
5. expanded_bytes[0] |= 0x01 // Set bottom-most bit
6. expanded_bytes[lambda_len-1] &= 0x3F // Clear two-most top bits
7. e' = bytes_to_int(slice(expanded_bytes, lambda_len))
8. output pkM = (n, e')
~~~

## Private Key Augmentation {#augment-private-key}

The public key augmentation function (AugmentPrivateKey) derives a per-metadata private
signing key that is used by the server in the core protocol.

~~~
AugmentPrivateKey(skS, pkS, info)

Parameters:
- kLen, the length in bytes of the RSA modulus n
- Hash, the hash function used to hash the message

Inputs:
- skS, server private key (p, q, phi, d)
- pkS, server public key (n, e)
- info, public metadata, a byte string

Outputs:
- skM, augmented server private key (p, q, phi, d')

Steps:
1. (n, e') = AugmentPublicKey(pkS, info)
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

[[TODO: writeme]]

# Security Considerations

[[TODO: writeme]]

# IANA Considerations

This document has no IANA actions.

--- back

# Test Vectors

[[TODO: writeme]]

# Acknowledgments
{:numbered="false"}

[[TODO: writeme]]
