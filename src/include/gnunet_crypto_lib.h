/*
     This file is part of GNUnet.
     Copyright (C) 2001-2023 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @file include/gnunet_crypto_lib.h
 * @brief cryptographic primitives for GNUnet
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 * @author Jeffrey Burdges <burdges@gnunet.org>
 *
 * @defgroup crypto  Crypto library: cryptographic operations
 * Provides cryptographic primitives.
 *
 * @see [Documentation](https://gnunet.org/crypto-api)
 *
 * @defgroup hash  Crypto library: hash operations
 * Provides hashing and operations on hashes.
 *
 * @see [Documentation](https://gnunet.org/crypto-api)
 */

#if ! defined (__GNUNET_UTIL_LIB_H_INSIDE__)
#error "Only <gnunet_util_lib.h> can be included directly."
#endif

#ifndef GNUNET_CRYPTO_LIB_H
#define GNUNET_CRYPTO_LIB_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include <stdbool.h>
#include <sodium.h>

/**
 * The identity of the host (wraps the signing key of the peer).
 */
struct GNUNET_PeerIdentity;

#include <gcrypt.h>


/**
 * Maximum length of an ECC signature.
 * Note: round up to multiple of 8 minus 2 for alignment.
 */
#define GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH 126


/**
 * Desired quality level for random numbers.
 * @ingroup crypto
 */
enum GNUNET_CRYPTO_Quality
{
  /**
   * No good quality of the operation is needed (i.e.,
   * random numbers can be pseudo-random).
   * @ingroup crypto
   */
  GNUNET_CRYPTO_QUALITY_WEAK,

  /**
   * High-quality operations are desired.
   * @ingroup crypto
   */
  GNUNET_CRYPTO_QUALITY_STRONG,

  /**
   * Randomness for IVs etc. is required.
   * @ingroup crypto
   */
  GNUNET_CRYPTO_QUALITY_NONCE
};


/**
 * @brief length of the sessionkey in bytes (256 BIT sessionkey)
 */
#define GNUNET_CRYPTO_AES_KEY_LENGTH (256 / 8)

/**
 * Length of a hash value
 */
#define GNUNET_CRYPTO_HASH_LENGTH (512 / 8)

/**
 * How many characters (without 0-terminator) are our ASCII-encoded
 * public keys (ECDSA/EDDSA/ECDHE).
 */
#define GNUNET_CRYPTO_PKEY_ASCII_LENGTH 52

/**
 * @brief 0-terminated ASCII encoding of a struct GNUNET_HashCode.
 */
struct GNUNET_CRYPTO_HashAsciiEncoded
{
  unsigned char encoding[104];
};


GNUNET_NETWORK_STRUCT_BEGIN


/**
 * @brief header of what an ECC signature signs
 *        this must be followed by "size - 8" bytes of
 *        the actual signed data
 */
struct GNUNET_CRYPTO_EccSignaturePurpose
{
  /**
   * How many bytes does this signature sign?
   * (including this purpose header); in network
   * byte order (!).
   */
  uint32_t size GNUNET_PACKED;

  /**
   * What does this signature vouch for?  This
   * must contain a GNUNET_SIGNATURE_PURPOSE_XXX
   * constant (from gnunet_signatures.h).  In
   * network byte order!
   */
  uint32_t purpose GNUNET_PACKED;
};


/**
 * @brief an ECC signature using EdDSA.
 * See cr.yp.to/papers.html#ed25519
 */
struct GNUNET_CRYPTO_EddsaSignature
{
  /**
   * R value.
   */
  unsigned char r[256 / 8];

  /**
   * S value.
   */
  unsigned char s[256 / 8];
};


/**
 * @brief an ECC signature using ECDSA
 */
struct GNUNET_CRYPTO_EcdsaSignature
{
  /**
   * R value.
   */
  unsigned char r[256 / 8];

  /**
   * S value.
   */
  unsigned char s[256 / 8];
};


/**
 * Public ECC key (always for curve Ed25519) encoded in a format
 * suitable for network transmission and EdDSA signatures.  Refer
 * to section 5.1.3 of rfc8032, for a thorough explanation of how
 * this value maps to the x- and y-coordinates.
 */
struct GNUNET_CRYPTO_EddsaPublicKey
{
  /**
   * Point Q consists of a y-value mod p (256 bits); the x-value is
   * always positive. The point is stored in Ed25519 standard
   * compact format.
   */
  unsigned char q_y[256 / 8];
};


/**
 * Public ECC key (always for Curve25519) encoded in a format suitable
 * for network transmission and ECDSA signatures.
 */
struct GNUNET_CRYPTO_EcdsaPublicKey
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits), given
   * here in affine coordinates and Ed25519 standard compact format.
   */
  unsigned char q_y[256 / 8];
};


/**
 * The identity of the host (wraps the signing key of the peer).
 */
struct GNUNET_PeerIdentity
{
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;
};


/**
 * Public ECC key (always for Curve25519) encoded in a format suitable
 * for network transmission and encryption (ECDH),
 * See http://cr.yp.to/ecdh.html
 */
struct GNUNET_CRYPTO_EcdhePublicKey
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits), given
   * here in affine coordinates and Ed25519 standard compact format.
   */
  unsigned char q_y[256 / 8];
};


/**
 * Private ECC key encoded for transmission.  To be used only for ECDH
 * key exchange (ECDHE to be precise).
 */
struct GNUNET_CRYPTO_EcdhePrivateKey
{
  /**
   * d is a value mod n, where n has at most 256 bits.
   */
  unsigned char d[256 / 8];
};

/**
 * Private ECC key encoded for transmission.  To be used only for ECDSA
 * signatures.
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey
{
  /**
   * d is a value mod n, where n has at most 256 bits.
   */
  unsigned char d[256 / 8];
};

/**
 * Private ECC key encoded for transmission.  To be used only for EdDSA
 * signatures.
 */
struct GNUNET_CRYPTO_EddsaPrivateKey
{
  /**
   * d is a value mod n, where n has at most 256 bits.
   */
  unsigned char d[256 / 8];
};


/**
 * Private ECC scalar encoded for transmission.  To be used only for EdDSA
 * signatures.
 */
struct GNUNET_CRYPTO_EddsaPrivateScalar
{
  /**
   * s is the expandedprivate 512-bit scalar of a private key.
   */
  unsigned char s[512 / 8];
};

/**
 * Private ECC key material encoded for transmission.  To be used only for
 * Edx25519 signatures.  An initial key corresponds to data from the key
 * expansion and clamping in the EdDSA key generation.
 */
struct GNUNET_CRYPTO_Edx25519PrivateKey
{
  /**
   * a is a value mod n, where n has at most 256 bits.  It is the first half of
   * the seed-expansion of EdDSA and will be clamped.
   */
  unsigned char a[256 / 8];

  /**
   * b consists of 32 bytes which where originally the lower 32bytes of the key
   * expansion.  Subsequent calls to derive_private will change this value, too.
   */
  unsigned char b[256 / 8];
};


/**
 * Public ECC key (always for curve Ed25519) encoded in a format suitable for
 * network transmission and Edx25519 (same as EdDSA) signatures.  Refer to
 * section 5.1.3 of rfc8032, for a thorough explanation of how this value maps
 * to the x- and y-coordinates.
 */
struct GNUNET_CRYPTO_Edx25519PublicKey
{
  /**
   * Point Q consists of a y-value mod p (256 bits); the x-value is
   * always positive. The point is stored in Ed25519 standard
   * compact format.
   */
  unsigned char q_y[256 / 8];
};

/**
 * @brief an ECC signature using Edx25519 (same as in EdDSA).
 */
struct GNUNET_CRYPTO_Edx25519Signature
{
  /**
   * R value.
   */
  unsigned char r[256 / 8];

  /**
   * S value.
   */
  unsigned char s[256 / 8];
};

/**
 * Special private ECC key generated by GNUNET_CRYPTO_ecdhe_elligator_key_create.
 * To be used only for the Elligator KEM.
 * Encoded for transmission.
 */
struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey
{
  /**
   * d is a value mod n, where n has at most 256 bits.
   */
  unsigned char d[256 / 8];
};

/**
 * Elligator representative (always for Curve25519)
 */
struct GNUNET_CRYPTO_ElligatorRepresentative
{
  /**
   * Represents an element of Curve25519 finite field.
   * Always smaller than 2 ^ 254 - 10 -> Needs to be serialized into a random-looking byte stream before transmission.
   */
  uint8_t r[256 / 8];
};

/**
 * Key type for the generic public key union
 */
enum GNUNET_CRYPTO_KeyType
{
  /**
   * The identity type. The value is the same as the
   * PKEY record type.
   */
  GNUNET_PUBLIC_KEY_TYPE_ECDSA = 65536,

  /**
   * EDDSA identity. The value is the same as the EDKEY
   * record type.
   */
  GNUNET_PUBLIC_KEY_TYPE_EDDSA = 65556
};

/**
 * A private key for an identity as per LSD0001.
 * Note that these types are NOT packed and MUST NOT be used in RPC
 * messages. Use the respective serialization functions.
 */
struct GNUNET_CRYPTO_PrivateKey
{
  /**
   * Type of public key.
   * Defined by the GNS zone type value.
   * In NBO.
   */
  uint32_t type;

  union
  {
    /**
     * An ECDSA identity key.
     */
    struct GNUNET_CRYPTO_EcdsaPrivateKey ecdsa_key;

    /**
     * AN EdDSA identtiy key
     */
    struct GNUNET_CRYPTO_EddsaPrivateKey eddsa_key;
  };
};


/**
 * An identity key as per LSD0001.
 */
struct GNUNET_CRYPTO_PublicKey
{
  /**
   * Type of public key.
   * Defined by the GNS zone type value.
   * In NBO.
   */
  uint32_t type;

  union
  {
    /**
     * An ECDSA identity key.
     */
    struct GNUNET_CRYPTO_EcdsaPublicKey ecdsa_key;

    /**
     * AN EdDSA identtiy key
     */
    struct GNUNET_CRYPTO_EddsaPublicKey eddsa_key;
  };
};


/**
 * An identity signature as per LSD0001.
 */
struct GNUNET_CRYPTO_Signature
{
  /**
   * Type of signature.
   * Defined by the GNS zone type value.
   * In NBO.
   */
  uint32_t type;

  union
  {
    /**
     * An ECDSA signature
     */
    struct GNUNET_CRYPTO_EcdsaSignature ecdsa_signature;

    /**
     * AN EdDSA signature
     */
    struct GNUNET_CRYPTO_EddsaSignature eddsa_signature;
  };
};

/**
 * @brief type for session keys
 */
struct GNUNET_CRYPTO_SymmetricSessionKey
{
  /**
   * Actual key for AES.
   */
  unsigned char aes_key[GNUNET_CRYPTO_AES_KEY_LENGTH];

  /**
   * Actual key for TwoFish.
   */
  unsigned char twofish_key[GNUNET_CRYPTO_AES_KEY_LENGTH];
};

/**
 * Type of a nonce used for challenges.
 */
struct GNUNET_CRYPTO_ChallengeNonceP
{
  /**
   * The value of the nonce.  Note that this is NOT a hash.
   */
  struct GNUNET_ShortHashCode value;
};

GNUNET_NETWORK_STRUCT_END

/**
 * @brief IV for sym cipher
 *
 * NOTE: must be smaller (!) in size than the
 * `struct GNUNET_HashCode`.
 */
struct GNUNET_CRYPTO_SymmetricInitializationVector
{
  unsigned char aes_iv[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];

  unsigned char twofish_iv[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
};


/**
 * @brief type for (message) authentication keys
 */
struct GNUNET_CRYPTO_AuthKey
{
  unsigned char key[GNUNET_CRYPTO_HASH_LENGTH];
};


/**
 * Size of paillier plain texts and public keys.
 * Private keys and ciphertexts are twice this size.
 */
#define GNUNET_CRYPTO_PAILLIER_BITS 2048


/**
 * Paillier public key.
 */
struct GNUNET_CRYPTO_PaillierPublicKey
{
  /**
   * N value.
   */
  unsigned char n[GNUNET_CRYPTO_PAILLIER_BITS / 8];
};


/**
 * Paillier private key.
 */
struct GNUNET_CRYPTO_PaillierPrivateKey
{
  /**
   * Lambda-component of the private key.
   */
  unsigned char lambda[GNUNET_CRYPTO_PAILLIER_BITS / 8];
  /**
   * Mu-component of the private key.
   */
  unsigned char mu[GNUNET_CRYPTO_PAILLIER_BITS / 8];
};


/**
 * Paillier ciphertext.
 */
struct GNUNET_CRYPTO_PaillierCiphertext
{
  /**
   * Guaranteed minimum number of homomorphic operations with this ciphertext,
   * in network byte order (NBO).
   */
  int32_t remaining_ops GNUNET_PACKED;

  /**
   * The bits of the ciphertext.
   */
  unsigned char bits[GNUNET_CRYPTO_PAILLIER_BITS * 2 / 8];
};


/**
 * Curve25519 Scalar
 */
struct GNUNET_CRYPTO_Cs25519Scalar
{
  /**
   * 32 byte scalar
   */
  unsigned char d[crypto_core_ed25519_SCALARBYTES];
};


/**
 * Curve25519 point
 */
struct GNUNET_CRYPTO_Cs25519Point
{
  /**
   * This is a point on the Curve25519.
   * The x coordinate can be restored using the y coordinate
   */
  unsigned char y[crypto_core_ed25519_BYTES];
};


/**
 * The private information of an Schnorr key pair.
 */
struct GNUNET_CRYPTO_CsPrivateKey
{
  struct GNUNET_CRYPTO_Cs25519Scalar scalar;
};


/**
 * The public information of an Schnorr key pair.
 */
struct GNUNET_CRYPTO_CsPublicKey
{
  struct GNUNET_CRYPTO_Cs25519Point point;
};


/**
 * Secret used for blinding (alpha and beta).
 */
struct GNUNET_CRYPTO_CsBlindingSecret
{
  struct GNUNET_CRYPTO_Cs25519Scalar alpha;
  struct GNUNET_CRYPTO_Cs25519Scalar beta;
};


/**
 * the private r used in the signature
 */
struct GNUNET_CRYPTO_CsRSecret
{
  struct GNUNET_CRYPTO_Cs25519Scalar scalar;
};


/**
 * the public R (derived from r) used in c
 */
struct GNUNET_CRYPTO_CsRPublic
{
  struct GNUNET_CRYPTO_Cs25519Point point;
};


/**
 * Schnorr c to be signed
 */
struct GNUNET_CRYPTO_CsC
{
  struct GNUNET_CRYPTO_Cs25519Scalar scalar;
};


/**
 * s in the signature
 */
struct GNUNET_CRYPTO_CsS
{
  struct GNUNET_CRYPTO_Cs25519Scalar scalar;
};


/**
 * blinded s in the signature
 */
struct GNUNET_CRYPTO_CsBlindS
{
  struct GNUNET_CRYPTO_Cs25519Scalar scalar;
};


/**
 * CS Signtature containing scalar s and point R
 */
struct GNUNET_CRYPTO_CsSignature
{
  /**
   * Schnorr signatures are composed of a scalar s and a curve point
   */
  struct GNUNET_CRYPTO_CsS s_scalar;

  /**
   * Curve point of the Schnorr signature.
   */
  struct GNUNET_CRYPTO_CsRPublic r_point;
};


/**
 * Nonce for the session, picked by client,
 * shared with the signer.
 */
struct GNUNET_CRYPTO_CsSessionNonce
{
  /*a nonce*/
  unsigned char snonce[256 / 8];
};


/**
 * Nonce for computing blinding factors. Not
 * shared with the signer.
 */
struct GNUNET_CRYPTO_CsBlindingNonce
{
  /*a nonce*/
  unsigned char bnonce[256 / 8];
};


/* **************** Functions and Macros ************* */

/**
 * @ingroup crypto
 * Seed a weak random generator. Only #GNUNET_CRYPTO_QUALITY_WEAK-mode generator
 * can be seeded.
 *
 * @param seed the seed to use
 */
void
GNUNET_CRYPTO_seed_weak_random (int32_t seed);


/**
 * @ingroup hash
 * Calculate the checksum of a buffer in one step.
 *
 * @param buf buffer to calculate CRC over
 * @param len number of bytes in @a buf
 * @return crc8 value
 */
uint8_t
GNUNET_CRYPTO_crc8_n (const void *buf, size_t len);


/**
 * Perform an incremental step in a CRC16 (for TCP/IP) calculation.
 *
 * @param sum current sum, initially 0
 * @param buf buffer to calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in @a buf, must be multiple of 2
 * @return updated crc sum (must be subjected to #GNUNET_CRYPTO_crc16_finish to get actual crc16)
 */
uint32_t
GNUNET_CRYPTO_crc16_step (uint32_t sum, const void *buf, size_t len);


/**
 * Convert results from GNUNET_CRYPTO_crc16_step to final crc16.
 *
 * @param sum cumulative sum
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_finish (uint32_t sum);


/**
 * @ingroup hash
 * Calculate the checksum of a buffer in one step.
 *
 * @param buf buffer to calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in @a buf, must be multiple of 2
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_n (const void *buf, size_t len);


/**
 * @ingroup hash
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer @a buf in bytes
 * @return the resulting CRC32 checksum
 */
int32_t
GNUNET_CRYPTO_crc32_n (const void *buf, size_t len);

/**
 * @ingroup crypto
 * Zero out @a buffer, securely against compiler optimizations.
 * Used to delete key material.
 *
 * @param buffer the buffer to zap
 * @param length buffer length
 */
void
GNUNET_CRYPTO_zero_keys (void *buffer, size_t length);


/**
 * @ingroup crypto
 * Fill block with a random values.
 *
 * @param mode desired quality of the random number
 * @param[out] buffer the buffer to fill
 * @param length buffer length
 */
void
GNUNET_CRYPTO_random_block (enum GNUNET_CRYPTO_Quality mode,
                            void *buffer,
                            size_t length);


/**
 * @ingroup crypto
 * Fill UUID with a timeflake pseudo-random value.  Note that
 * timeflakes use only 80 bits of randomness and 48 bits
 * to encode a timestamp in milliseconds. So what we return
 * here is not a completely random number.
 *
 * @param mode desired quality of the random number
 * @param[out] uuid the value to fill
 */
void
GNUNET_CRYPTO_random_timeflake (enum GNUNET_CRYPTO_Quality mode,
                                struct GNUNET_Uuid *uuid);


/**
 * @ingroup crypto
 * Produce a random value.
 *
 * @param mode desired quality of the random number
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,@a i) (exclusive).
 */
uint32_t
GNUNET_CRYPTO_random_u32 (enum GNUNET_CRYPTO_Quality mode, uint32_t i);


/**
 * @ingroup crypto
 * Generate a random unsigned 64-bit value.
 *
 * @param mode desired quality of the random number
 * @param max value returned will be in range [0,@a max) (exclusive)
 * @return random 64-bit number
 */
uint64_t
GNUNET_CRYPTO_random_u64 (enum GNUNET_CRYPTO_Quality mode, uint64_t max);


/**
 * @ingroup crypto
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode #GNUNET_CRYPTO_QUALITY_STRONG if the strong (but expensive) PRNG should be used,
 *             #GNUNET_CRYPTO_QUALITY_WEAK or #GNUNET_CRYPTO_QUALITY_NONCE otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
unsigned int *
GNUNET_CRYPTO_random_permute (enum GNUNET_CRYPTO_Quality mode, unsigned int n);


/**
 * @ingroup crypto
 * Create a new random session key.
 *
 * @param key key to initialize
 */
void
GNUNET_CRYPTO_symmetric_create_session_key (
  struct GNUNET_CRYPTO_SymmetricSessionKey *key);


/**
 * @ingroup crypto
 * Encrypt a block using a symmetric sessionkey.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_CRYPTO_symmetric_encrypt (
  const void *block,
  size_t size,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
  const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
  void *result);


/**
 * @ingroup crypto
 * Decrypt a given block using a symmetric sessionkey.
 *
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size how big is the block?
 * @param sessionkey the key used to decrypt
 * @param iv the initialization vector to use
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
ssize_t
GNUNET_CRYPTO_symmetric_decrypt (
  const void *block,
  size_t size,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
  const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
  void *result);


/**
 * @ingroup crypto
 * @brief Derive an IV
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the @a salt
 * @param ... pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_symmetric_derive_iv (
  struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
  const void *salt,
  size_t salt_len,
  ...);


/**
 * @brief Derive an IV
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the @a salt
 * @param argp pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_symmetric_derive_iv_v (
  struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
  const void *salt,
  size_t salt_len,
  va_list argp);


/**
 * @ingroup hash
 * Convert hash to ASCII encoding.
 * @param block the hash code
 * @param result where to store the encoding (struct GNUNET_CRYPTO_HashAsciiEncoded can be
 *  safely cast to char*, a '\\0' termination is set).
 */
void
GNUNET_CRYPTO_hash_to_enc (const struct GNUNET_HashCode *block,
                           struct GNUNET_CRYPTO_HashAsciiEncoded *result);


/**
 * @ingroup hash
 * Convert ASCII encoding back to a 'struct GNUNET_HashCode'
 *
 * @param enc the encoding
 * @param enclen number of characters in @a enc (without 0-terminator, which can be missing)
 * @param result where to store the hash code
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hash_from_string2 (const char *enc,
                                 size_t enclen,
                                 struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * Convert ASCII encoding back to `struct GNUNET_HashCode`
 *
 * @param enc the encoding
 * @param result where to store the hash code
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
#define GNUNET_CRYPTO_hash_from_string(enc, result) \
  GNUNET_CRYPTO_hash_from_string2 (enc, strlen (enc), result)


/**
 * @ingroup hash
 *
 * Compute the distance between 2 hashcodes.  The
 * computation must be fast, not involve @a a[0] or @a a[4] (they're used
 * elsewhere), and be somewhat consistent. And of course, the result
 * should be a positive number.
 *
 * @param a some hash code
 * @param b some hash code
 * @return number between 0 and UINT32_MAX
 */
uint32_t
GNUNET_CRYPTO_hash_distance_u32 (const struct GNUNET_HashCode *a,
                                 const struct GNUNET_HashCode *b);


/**
 * @ingroup hash
 * Compute hash of a given block.
 *
 * @param block the data to hash
 * @param size size of the @a block
 * @param ret pointer to where to write the hashcode
 */
void
GNUNET_CRYPTO_hash (const void *block,
                    size_t size,
                    struct GNUNET_HashCode *ret);


/**
 * Value for a salt for #GNUNET_CRYPTO_pow_hash().
 */
struct GNUNET_CRYPTO_PowSalt
{
  char salt[crypto_pwhash_argon2id_SALTBYTES];
};


/**
 * Calculate the 'proof-of-work' hash (an expensive hash).
 *
 * @param salt salt for the hash. Must be crypto_pwhash_argon2id_SALTBYTES long.
 * @param buf data to hash
 * @param buf_len number of bytes in @a buf
 * @param result where to write the resulting hash
 */
void
GNUNET_CRYPTO_pow_hash (const struct GNUNET_CRYPTO_PowSalt *salt,
                        const void *buf,
                        size_t buf_len,
                        struct GNUNET_HashCode *result);


/**
 * Context for cumulative hashing.
 */
struct GNUNET_HashContext;


/**
 * Start incremental hashing operation.
 *
 * @return context for incremental hash computation
 */
struct GNUNET_HashContext *
GNUNET_CRYPTO_hash_context_start (void);


/**
 * Make a copy of the hash computation.
 *
 * @param hc hash context to use (to continue hashing independently)
 * @return copy of @a hc
 */
struct GNUNET_HashContext *
GNUNET_CRYPTO_hash_context_copy (const struct GNUNET_HashContext *hc);


/**
 * Add data to be hashed.
 *
 * @param hc cumulative hash context
 * @param buf data to add
 * @param size number of bytes in @a buf
 */
void
GNUNET_CRYPTO_hash_context_read (struct GNUNET_HashContext *hc,
                                 const void *buf,
                                 size_t size);


/**
 * Finish the hash computation.
 *
 * @param hc hash context to use, is freed in the process
 * @param r_hash where to write the latest / final hash code
 */
void
GNUNET_CRYPTO_hash_context_finish (struct GNUNET_HashContext *hc,
                                   struct GNUNET_HashCode *r_hash);


/**
 * Abort hashing, do not bother calculating final result.
 *
 * @param hc hash context to destroy
 */
void
GNUNET_CRYPTO_hash_context_abort (struct GNUNET_HashContext *hc);


/**
 * Calculate HMAC of a message (RFC 2104)
 * TODO: Shouldn't this be the standard hmac function and
 * the above be renamed?
 *
 * @param key secret key
 * @param key_len secret key length
 * @param plaintext input plaintext
 * @param plaintext_len length of @a plaintext
 * @param hmac where to store the hmac
 */
void
GNUNET_CRYPTO_hmac_raw (const void *key,
                        size_t key_len,
                        const void *plaintext,
                        size_t plaintext_len,
                        struct GNUNET_HashCode *hmac);


/**
 * @ingroup hash
 * Calculate HMAC of a message (RFC 2104)
 *
 * @param key secret key
 * @param plaintext input plaintext
 * @param plaintext_len length of @a plaintext
 * @param hmac where to store the hmac
 */
void
GNUNET_CRYPTO_hmac (const struct GNUNET_CRYPTO_AuthKey *key,
                    const void *plaintext,
                    size_t plaintext_len,
                    struct GNUNET_HashCode *hmac);


/**
 * Function called once the hash computation over the
 * specified file has completed.
 *
 * @param cls closure
 * @param res resulting hash, NULL on error
 */
typedef void
(*GNUNET_CRYPTO_HashCompletedCallback) (
  void *cls,
  const struct GNUNET_HashCode *res);


/**
 * Handle to file hashing operation.
 */
struct GNUNET_CRYPTO_FileHashContext;


/**
 * @ingroup hash
 * Compute the hash of an entire file.
 *
 * @param priority scheduling priority to use
 * @param filename name of file to hash
 * @param blocksize number of bytes to process in one task
 * @param callback function to call upon completion
 * @param callback_cls closure for @a callback
 * @return NULL on (immediate) error
 */
struct GNUNET_CRYPTO_FileHashContext *
GNUNET_CRYPTO_hash_file (enum GNUNET_SCHEDULER_Priority priority,
                         const char *filename,
                         size_t blocksize,
                         GNUNET_CRYPTO_HashCompletedCallback callback,
                         void *callback_cls);


/**
 * Cancel a file hashing operation.
 *
 * @param fhc operation to cancel (callback must not yet have been invoked)
 */
void
GNUNET_CRYPTO_hash_file_cancel (struct GNUNET_CRYPTO_FileHashContext *fhc);


/**
 * @ingroup hash
 * Create a random hash code.
 *
 * @param mode desired quality level
 * @param result hash code that is randomized
 */
void
GNUNET_CRYPTO_hash_create_random (enum GNUNET_CRYPTO_Quality mode,
                                  struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * compute @a result = @a b - @a a
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to @a b - @a a
 */
void
GNUNET_CRYPTO_hash_difference (const struct GNUNET_HashCode *a,
                               const struct GNUNET_HashCode *b,
                               struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * compute @a result = @a a + @a delta
 *
 * @param a some hash code
 * @param delta some hash code
 * @param result set to @a a + @a delta
 */
void
GNUNET_CRYPTO_hash_sum (const struct GNUNET_HashCode *a,
                        const struct GNUNET_HashCode *delta,
                        struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * compute result = a ^ b
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to @a a ^ @a b
 */
void
GNUNET_CRYPTO_hash_xor (const struct GNUNET_HashCode *a,
                        const struct GNUNET_HashCode *b,
                        struct GNUNET_HashCode *result);


/**
 * Count the number of leading 0 bits in @a h.
 *
 * @param h a hash
 * @return number of leading 0 bits in @a h
 */
unsigned int
GNUNET_CRYPTO_hash_count_leading_zeros (const struct GNUNET_HashCode *h);


/**
 * Count the number of tailing 0 bits in @a h.
 *
 * @param h a hash
 * @return number of tailing 0 bits in @a h
 */
unsigned int
GNUNET_CRYPTO_hash_count_tailing_zeros (const struct GNUNET_HashCode *h);


/**
 * @ingroup hash
 * Convert a hashcode into a key.
 *
 * @param hc hash code that serves to generate the key
 * @param skey set to a valid session key
 * @param iv set to a valid initialization vector
 */
void
GNUNET_CRYPTO_hash_to_aes_key (
  const struct GNUNET_HashCode *hc,
  struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
  struct GNUNET_CRYPTO_SymmetricInitializationVector *iv);


/**
 * @ingroup hash
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @return 1 if @a h1 > @a h2, -1 if @a h1 < @a h2 and 0 if @a h1 == @a h2.
 */
int
GNUNET_CRYPTO_hash_cmp (const struct GNUNET_HashCode *h1,
                        const struct GNUNET_HashCode *h2);


/**
 * @ingroup hash
 * Find out which of the two GNUNET_CRYPTO_hash codes is closer to target
 * in the XOR metric (Kademlia).
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @param target some hash code
 * @return -1 if @a h1 is closer, 1 if @a h2 is closer and 0 if @a h1== @a h2.
 */
int
GNUNET_CRYPTO_hash_xorcmp (const struct GNUNET_HashCode *h1,
                           const struct GNUNET_HashCode *h2,
                           const struct GNUNET_HashCode *target);


/**
 * @ingroup hash
 * @brief Derive an authentication key
 * @param key authentication key
 * @param rkey root key
 * @param salt salt
 * @param salt_len size of the salt
 * @param argp pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key_v (
  struct GNUNET_CRYPTO_AuthKey *key,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
  const void *salt,
  size_t salt_len,
  va_list argp);


/**
 * @ingroup hash
 * @brief Derive an authentication key
 * @param key authentication key
 * @param rkey root key
 * @param salt salt
 * @param salt_len size of the salt
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key (
  struct GNUNET_CRYPTO_AuthKey *key,
  const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
  const void *salt,
  size_t salt_len,
  ...);


/**
 * @ingroup hash
 * @brief HKDF-Extract using SHA256. RFC 5869
 * @param prk the PRK
 * @param salt salt
 * @param salt_len length of @a xts
 * @param ikm source key material
 * @param ikm_len length of @a skm
 * @return #GNUNET_YES on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_extract (struct GNUNET_ShortHashCode *prk,
                            const void *salt,
                            size_t salt_len,
                            const void *ikm,
                            size_t ikm_len);

/**
 * @ingroup hash
 * @brief HKDF-Expand using SHA256. RFC 5869
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 * @return #GNUNET_YES on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_expand (void *result,
                           size_t out_len,
                           const struct GNUNET_ShortHashCode *prk,
                           ...);

/**
 * @ingroup hash
 * @brief HKDF-Expand using SHA256. See #GNUNET_CRYPTO_hkdf_expand
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_expand_v (void *result,
                             size_t out_len,
                             const struct GNUNET_ShortHashCode *prk,
                             va_list argp);


/**
 * @ingroup hash
 * @brief A peculiar HKDF instantiation that tried to mimic Truncated NMAC.
 * But, what it actually does is HKDF-Extract with SHA512 and instead of
 * truncating the PRK, it uses it as a 64 byte key in the HKDF-Expand
 * phase with SHA256.
 * (Truncated NMAC would require us to, well, truncate it to 32 byte.)
 * ONLY USE FOR COMPATIBILITY WITH OLDER KEY DERIVATIONS.
 * Use the more standard #GNUNET_CRYPTO_hkdf_extract and
 * #GNUNET_CRYPTO_HKDF_expand instead!
 *
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 * @return #GNUNET_YES on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_gnunet (void *result,
                           size_t out_len,
                           const void *xts,
                           size_t xts_len,
                           const void *skm,
                           size_t skm_len,
                           ...);


/**
 * @ingroup hash
 * @brief Derive key. See #GNUNET_CRYPTO_hkdf_gnunet
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hkdf_gnunet_v (void *result,
                             size_t out_len,
                             const void *xts,
                             size_t xts_len,
                             const void *skm,
                             size_t skm_len,
                             va_list argp);


/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_kdf_v (void *result,
                     size_t out_len,
                     const void *xts,
                     size_t xts_len,
                     const void *skm,
                     size_t skm_len,
                     va_list argp);


/**
 * Deterministically generate a pseudo-random number uniformly from the
 * integers modulo a libgcrypt mpi.
 *
 * @param[out] r MPI value set to the FDH
 * @param n MPI to work modulo
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param ctx context string
 */
void
GNUNET_CRYPTO_kdf_mod_mpi (gcry_mpi_t *r,
                           gcry_mpi_t n,
                           const void *xts,
                           size_t xts_len,
                           const void *skm,
                           size_t skm_len,
                           const char *ctx);


/**
 * @ingroup hash
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param ... void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_kdf (void *result,
                   size_t out_len,
                   const void *xts,
                   size_t xts_len,
                   const void *skm,
                   size_t skm_len,
                   ...);


/**
 * @ingroup crypto
 * Extract the public key for the given private key.
 *
 * @param priv the special elligator private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecdsa_key_get_public (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  struct GNUNET_CRYPTO_EcdsaPublicKey *pub);

/**
 * @ingroup crypto
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_eddsa_key_get_public (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  struct GNUNET_CRYPTO_EddsaPublicKey *pub);

/**
 * @ingroup crypto
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_edx25519_key_get_public (
  const struct GNUNET_CRYPTO_Edx25519PrivateKey *priv,
  struct GNUNET_CRYPTO_Edx25519PublicKey *pub);

/**
 * @ingroup crypto
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecdhe_key_get_public (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
  struct GNUNET_CRYPTO_EcdhePublicKey *pub);


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing @a pub
 */
char *
GNUNET_CRYPTO_ecdsa_public_key_to_string (
  const struct GNUNET_CRYPTO_EcdsaPublicKey *pub);

/**
 * Convert a private key to a string.
 *
 * @param priv key to convert
 * @return string representing @a priv
 */
char *
GNUNET_CRYPTO_ecdsa_private_key_to_string (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv);


/**
 * Convert a private key to a string.
 *
 * @param priv key to convert
 * @return string representing @a pub
 */
char *
GNUNET_CRYPTO_eddsa_private_key_to_string (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv);


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing @a pub
 */
char *
GNUNET_CRYPTO_eddsa_public_key_to_string (
  const struct GNUNET_CRYPTO_EddsaPublicKey *pub);


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param pub where to store the public key
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_public_key_from_string (
  const char *enc,
  size_t enclen,
  struct GNUNET_CRYPTO_EcdsaPublicKey *pub);


/**
 * Convert a string representing a private key to a private key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param priv where to store the private key
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_private_key_from_string (
  const char *enc,
  size_t enclen,
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv);


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param pub where to store the public key
 * @return #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_public_key_from_string (
  const char *enc,
  size_t enclen,
  struct GNUNET_CRYPTO_EddsaPublicKey *pub);


/**
 * @ingroup crypto
 * @brief Create a new private key by reading it from a file.
 *
 * If the files does not exist and @a do_create is set, creates a new key and
 * write it to the file.
 *
 * If the contents of the file are invalid, an error is returned.
 *
 * @param filename name of file to use to store the key
 * @param do_create should a file be created?
 * @param[out] pkey set to the private key from @a filename on success
 * @return #GNUNET_OK on success, #GNUNET_NO if @a do_create was set but
 *         we found an existing file, #GNUNET_SYSERR on failure
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_key_from_file (const char *filename,
                                   int do_create,
                                   struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey);


/**
 * @ingroup crypto
 * @brief Create a new private key by reading it from a file.
 *
 * If the files does not exist and @a do_create is set, creates a new key and
 * write it to the file.
 *
 * If the contents of the file are invalid, an error is returned.
 *
 * @param filename name of file to use to store the key
 * @param do_create should a file be created?
 * @param[out] pkey set to the private key from @a filename on success
 * @return #GNUNET_OK on success, #GNUNET_NO if @a do_create was set but
 *         we found an existing file, #GNUNET_SYSERR on failure
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_key_from_file (const char *filename,
                                   int do_create,
                                   struct GNUNET_CRYPTO_EddsaPrivateKey *pkey);


/**
 * Forward declaration to simplify #include-structure.
 */
struct GNUNET_CONFIGURATION_Handle;


/**
 * @ingroup crypto
 * Create a new private key by reading our peer's key from
 * the file specified in the configuration.
 *
 * @param cfg the configuration to use
 * @return new private key, NULL on error (for example,
 *   permission denied); free using #GNUNET_free
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_CRYPTO_eddsa_key_create_from_configuration (
  const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * @ingroup crypto
 * Create a new private key.
 *
 * @param[out] pk private key to initialize
 */
void
GNUNET_CRYPTO_ecdsa_key_create (struct GNUNET_CRYPTO_EcdsaPrivateKey *pk);


/**
 * @ingroup crypto
 * Create a new private key.
 *
 * @param[out] pk private key to initialize
 */
void
GNUNET_CRYPTO_eddsa_key_create (struct GNUNET_CRYPTO_EddsaPrivateKey *pk);


/**
 * @ingroup crypto
 * Create a new private key.
 *
 * @param[out] pk private key to initialize
 */
void
GNUNET_CRYPTO_edx25519_key_create (struct GNUNET_CRYPTO_Edx25519PrivateKey *pk);

/**
 * @ingroup crypto
 * Create a new private key for Edx25519 from a given seed.  After expanding
 * the seed, the first half of the key will be clamped according to EdDSA.
 *
 * @param seed seed input
 * @param seedsize size of the seed in bytes
 * @param[out] pk private key to initialize
 */
void
GNUNET_CRYPTO_edx25519_key_create_from_seed (
  const void *seed,
  size_t seedsize,
  struct GNUNET_CRYPTO_Edx25519PrivateKey *pk);

/**
 * @ingroup crypto
 * Create a new private key.  Clear with #GNUNET_CRYPTO_ecdhe_key_clear().
 * This is X25519 DH (RFC 7748 Section 5) and corresponds to
 * X25519(a,9).
 * See #GNUNET_CRYPTO_ecc_ecdh for the DH function.
 *
 * @param[out] pk set to fresh private key;
 */
void
GNUNET_CRYPTO_ecdhe_key_create (struct GNUNET_CRYPTO_EcdhePrivateKey *pk);


/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_eddsa_key_clear (struct GNUNET_CRYPTO_EddsaPrivateKey *pk);


/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_ecdsa_key_clear (struct GNUNET_CRYPTO_EcdsaPrivateKey *pk);

/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_edx25519_key_clear (struct GNUNET_CRYPTO_Edx25519PrivateKey *pk);

/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_ecdhe_key_clear (struct GNUNET_CRYPTO_EcdhePrivateKey *pk);

/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_private_key_clear (struct GNUNET_CRYPTO_PrivateKey *pk);


/**
 * @ingroup crypto
 * Get the shared private key we use for anonymous users.
 *
 * @return "anonymous" private key; do not free
 */
const struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_key_get_anonymous (void);


/**
 * @ingroup crypto
 * Setup a hostkey file for a peer given the name of the
 * configuration file (!).  This function is used so that
 * at a later point code can be certain that reading a
 * hostkey is fast (for example in time-dependent testcases).
 *
 * @param cfg_name name of the configuration file to use
 */
void
GNUNET_CRYPTO_eddsa_setup_hostkey (const char *cfg_name);


/**
 * @ingroup crypto
 * Retrieve the identity of the host's peer.
 *
 * @param cfg configuration to use
 * @param dst pointer to where to write the peer identity
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the identity
 *         could not be retrieved
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_get_peer_identity (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 struct GNUNET_PeerIdentity *dst);


/**
 * @ingroup crypto
 * Sign a given block with a specific purpose using the host's peer identity.
 *
 * @param cfg configuration to use
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the identity
 *         could not be retrieved
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_sign_by_peer_identity (const struct
                                     GNUNET_CONFIGURATION_Handle *cfg,
                                     const struct
                                     GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                                     struct GNUNET_CRYPTO_EddsaSignature *sig);


/**
 * @ingroup crypto
 * Verify a given signature with a peer's identity.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param identity the peer's identity to verify
 * @return #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_verify_peer_identity (uint32_t purpose,
                                    const struct
                                    GNUNET_CRYPTO_EccSignaturePurpose *validate,
                                    const struct
                                    GNUNET_CRYPTO_EddsaSignature *sig,
                                    const struct GNUNET_PeerIdentity *identity);


/**
 * Internal structure used to cache pre-calculated values for DLOG calculation.
 */
struct GNUNET_CRYPTO_EccDlogContext;


/**
 * Point on a curve (always for Curve25519) encoded in a format suitable
 * for network transmission (ECDH), see http://cr.yp.to/ecdh.html.
 */
struct GNUNET_CRYPTO_EccPoint
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits), given
   * here in affine coordinates and Ed25519 standard compact format.
   */
  unsigned char v[256 / 8];
};

/**
 * A ECC scalar for use in point multiplications
 */
struct GNUNET_CRYPTO_EccScalar
{
  unsigned char v[256 / 8];
};

/**
 * Do pre-calculation for ECC discrete logarithm for small factors.
 *
 * @param max maximum value the factor can be
 * @param mem memory to use (should be smaller than @a max), must not be zero.
 * @return NULL on error
 */
struct GNUNET_CRYPTO_EccDlogContext *
GNUNET_CRYPTO_ecc_dlog_prepare (unsigned int max,
                                unsigned int mem);


/**
 * Calculate ECC discrete logarithm for small factors.
 * Opposite of #GNUNET_CRYPTO_ecc_dexp().
 *
 * @param edc precalculated values, determine range of factors
 * @param input point on the curve to factor
 * @return INT_MAX if dlog failed, otherwise the factor
 */
int
GNUNET_CRYPTO_ecc_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc,
                        const struct GNUNET_CRYPTO_EccPoint *input);


/**
 * Multiply the generator g of the elliptic curve by @a val
 * to obtain the point on the curve representing @a val.
 * Afterwards, point addition will correspond to integer
 * addition.  #GNUNET_CRYPTO_ecc_dlog() can be used to
 * convert a point back to an integer (as long as the
 * integer is smaller than the MAX of the @a edc context).
 *
 * @param val value to encode into a point
 * @param r where to write the point (must be allocated)
 */
void
GNUNET_CRYPTO_ecc_dexp (int val,
                        struct GNUNET_CRYPTO_EccPoint*r);


/**
 * Multiply the generator g of the elliptic curve by @a val
 * to obtain the point on the curve representing @a val.
 *
 * @param val (positive) value to encode into a point
 * @param r where to write the point (must be allocated)
 * @return #GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_dexp_mpi (const struct GNUNET_CRYPTO_EccScalar *val,
                            struct GNUNET_CRYPTO_EccPoint *r);


/**
 * Multiply the point @a p on the elliptic curve by @a val.
 *
 * @param p point to multiply
 * @param val (positive) value to encode into a point
 * @param r where to write the point (must be allocated)
 * @return #GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_pmul_mpi (const struct GNUNET_CRYPTO_EccPoint *p,
                            const struct GNUNET_CRYPTO_EccScalar *val,
                            struct GNUNET_CRYPTO_EccPoint *r);


/**
 * Add two points on the elliptic curve.
 *
 * @param a some value
 * @param b some value
 * @param r where to write the point (must be allocated)
 * @return #GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_add (const struct GNUNET_CRYPTO_EccPoint *a,
                       const struct GNUNET_CRYPTO_EccPoint *b,
                       struct GNUNET_CRYPTO_EccPoint *r);


/**
 * Obtain a random point on the curve and its
 * additive inverse.
 *
 * @param[out] r set to a random point on the curve
 * @param[out] r_inv set to the additive inverse of @a r
 * @return #GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_rnd (struct GNUNET_CRYPTO_EccPoint *r,
                       struct GNUNET_CRYPTO_EccPoint *r_inv);


/**
 * Obtain a random scalar for point multiplication on the curve and
 * its additive inverse.
 *
 * @param[out] r set to a random scalar on the curve
 * @param[out] r_neg set to the negation of @a
 */
void
GNUNET_CRYPTO_ecc_rnd_mpi (struct GNUNET_CRYPTO_EccScalar *r,
                           struct GNUNET_CRYPTO_EccScalar *r_neg);


/**
 * Generate a random value mod n.
 *
 * @param[out] r random value mod n.
 */
void
GNUNET_CRYPTO_ecc_random_mod_n (struct GNUNET_CRYPTO_EccScalar*r);


/**
 * Release precalculated values.
 *
 * @param dlc dlog context
 */
void
GNUNET_CRYPTO_ecc_dlog_release (struct GNUNET_CRYPTO_EccDlogContext *dlc);


/**
 * Create a scalar from int value.
 *
 * @param val the int value
 * @param[out] r where to write the salar
 */
void
GNUNET_CRYPTO_ecc_scalar_from_int (int64_t val,
                                   struct GNUNET_CRYPTO_EccScalar *r);


/**
 * @ingroup crypto
 * Derive key material from a public and a private ECC key.
 * This is X25519 DH (RFC 7748 Section 5) and corresponds to
 * H(X25519(b,X25519(a,9))) where b := priv, pub := X25519(a,9),
 * and a := #GNUNET_CRYPTO_ecdhe_key_create().
 *
 * @param priv private key to use for the ECDH (x)
 * @param pub public key to use for the ECDH (yG)
 * @param key_material where to write the key material (xyG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecc_ecdh (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                        const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                        struct GNUNET_HashCode *key_material);


/**
 * @ingroup crypto
 * Derive key material from a ECDH public key and a private EdDSA key.
 * Dual to #GNUNET_CRRYPTO_ecdh_eddsa.
 * This uses the Ed25519 private seed as X25519 seed.
 * As such, this also is a X25519 DH (see #GNUNET_CRYPTO_ecc_ecdh).
 * NOTE: Whenever you can get away with it, use separate key pairs
 * for signing and encryption (DH)!
 *
 * @param priv private key from EdDSA to use for the ECDH (x)
 * @param pub public key to use for the ECDH (yG)
 * @param key_material where to write the key material H(h(x)yG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_ecdh (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                          struct GNUNET_HashCode *key_material);


/**
 * @ingroup crypto
 * Derive key material from a ECDH public key and a private X25519 key.
 * Dual to #GNUNET_CRRYPTO_ecdh_x25519.
 * NOTE: Whenever you can get away with it, use separate key pairs
 * for signing and encryption (DH)!
 *
 * @param sk private key from X25519 to use for the ECDH (x)
 * @param pk public key to use for the ECDH (yG)
 * @param additional_data this is fed into HKDF-Extract along with
                          the ECDH shared secret
 * @param ad_len Length of the additional data
 * @param dh the DH shared secret (NOTE: Derive key from this before use!)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_x25519_ecdh (const struct GNUNET_CRYPTO_EcdhePrivateKey *sk,
                           const struct GNUNET_CRYPTO_EcdhePublicKey *pk,
                           struct GNUNET_CRYPTO_EcdhePublicKey *dh);


/** HPKE RFC 9180 **/

/**
 * The HPKE Mode
 * "PSK" stands for "Pre-Shared Key".
 * The "AUTH" variants use an authenticating KEM
 * construction.
 */
enum GNUNET_CRYPTO_HpkeMode
{
  GNUNET_CRYPTO_HPKE_MODE_BASE = 0x00,
  GNUNET_CRYPTO_HPKE_MODE_PSK = 0x01,
  GNUNET_CRYPTO_HPKE_MODE_AUTH = 0x02,
  GNUNET_CRYPTO_HPKE_MODE_AUTH_PSK = 0x03
};

// Nt
#define GNUNET_CRYPTO_HPKE_AEAD_ID 0x0003

// Nn
#define GNUNET_CRYPTO_HPKE_NONCE_LEN 12

// Nk
#define GNUNET_CRYPTO_HPKE_KEY_LEN 32

// Nt
#define GNUNET_CRYPTO_HPKE_TAG_LEN 16

// Overhead required for ciphertext
#define GNUNET_CRYPTO_HPKE_SEAL_OVERHEAD_BYTES GNUNET_CRYPTO_HPKE_TAG_LEN

// Overhead required for ciphertext
#define GNUNET_CRYPTO_HPKE_SEAL_ONESHOT_OVERHEAD_BYTES \
  GNUNET_CRYPTO_HPKE_SEAL_OVERHEAD_BYTES   \
  + sizeof (struct GNUNET_CRYPTO_HpkeEncapsulation)

/**
 * Role of the HPKE participant.
 */
enum GNUNET_CRYPTO_HpkeRole
{
  // Receiver
  GNUNET_CRYPTO_HPKE_ROLE_R = 0,
  // Sender
  GNUNET_CRYPTO_HPKE_ROLE_S = 1
};


/**
 * HPKE crypto context.
 */
struct GNUNET_CRYPTO_HpkeContext
{
  // Participant role
  enum GNUNET_CRYPTO_HpkeRole role;

  // Encapsulated/Decapsulated key
  uint8_t key[GNUNET_CRYPTO_HPKE_KEY_LEN];

  // Base nonce
  uint8_t base_nonce[GNUNET_CRYPTO_HPKE_NONCE_LEN];

  // Sequence number
  uint64_t seq;

  // Exporter secret
  struct GNUNET_ShortHashCode exporter_secret;
};

/**
 * HPKE KEM identifier
 * TODO: Elligator KEM was requested at IANA; Number is currently a placeholder.
 */
enum GNUNET_CRYPTO_HpkeKem
{
  // Non-elligator X25519 KEM using HKDF256
  GNUNET_CRYPTO_HPKE_KEM_DH_X25519_HKDF256 = 0x0020,
  // Elligator X25519 KEM using HKDF256
  GNUNET_CRYPTO_HPKE_KEM_DH_X25519ELLIGATOR_HKDF256 = 0x0030,
};


/**
 * HPKE DHKEM encapsulation (X25519)
 * See RFC 9180
 */
struct GNUNET_CRYPTO_HpkeEncapsulation
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits), given
   * here in affine coordinates and Ed25519 standard compact format.
   */
  unsigned char q_y[256 / 8];
};


/**
 * Convert a GNUnet identity key to a key sutiable for HPKE (X25519)
 *
 * @param sk the private key
 * @param x25519 the new key
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_sk_to_x25519 (const struct GNUNET_CRYPTO_PrivateKey *sk,
                                 struct GNUNET_CRYPTO_EcdhePrivateKey *x25519);


/**
 * Convert a GNUnet identity key to a key sutiable for HPKE (X25519)
 *
 * @param pk the public key
 * @param x25519 the new key
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_pk_to_x25519 (const struct GNUNET_CRYPTO_PublicKey *pk,
                                 struct GNUNET_CRYPTO_EcdhePublicKey *x25519);

/**
 * @ingroup crypto
 * Decapsulate a key for a private X25519 key.
 * Dual to #GNUNET_CRYPTO_hpke_kem_encaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param priv private key from X25519 to use for the ECDH (x)
 * @param c the encapsulated key
 * @param prk where to write the key material
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_kem_decaps (const struct
                               GNUNET_CRYPTO_EcdhePrivateKey *priv,
                               const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                               struct GNUNET_ShortHashCode *prk);

/**
 * @ingroup crypto
 * Encapsulate key material for a X25519 public key.
 * Dual to #GNUNET_CRYPTO_hpke_kem_decaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param pkR public key of receiver
 * @param c public key from X25519 to use for the ECDH (X=h(x)G)
 * @param prk where to write the key material
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_kem_encaps (const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
                               struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                               struct GNUNET_ShortHashCode *prk);

/**
 * @ingroup crypto
 * Deterministic variant of #GNUNET_CRYPTO_hpke_kem_encaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param pkR public key of receiver
 * @param c public key from X25519 to use for the ECDH (X=h(x)G)
 * @param skE ephemeral private key from X25519 to use
 * @param prk where to write the key material
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_kem_encaps_norand (const struct
                                      GNUNET_CRYPTO_EcdhePublicKey *pkR,
                                      struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                                      const struct
                                      GNUNET_CRYPTO_EcdhePrivateKey *skE,
                                      struct GNUNET_ShortHashCode *prk);

/**
 * @ingroup crypto
 * Encapsulate authenticated key material for a X25519 public key.
 * Deterministic variant of #GNUNET_CRYPTO_hpke_authkem_encaps.
 * Dual to #GNUNET_CRYPTO_hpke_authkem_decaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param pkR public key of receiver
 * @param skS secret of the authenticating sender
 * @param c public key from X25519 to use for the ECDH (X=h(x)G)
 * @param shared_secret where to write the key material
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_authkem_encaps_norand (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
  struct GNUNET_ShortHashCode *shared_secret);

/**
 * @ingroup crypto
 * Encapsulate authenticated key material for a X25519 public key.
 * Dual to #GNUNET_CRYPTO_hpke_kem_encaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param pkR public key of receiver
 * @param skS secret of the authenticating sender
 * @param c public key from X25519 to use for the ECDH (X=h(x)G)
 * @param shared_secret where to write the key material
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_authkem_encaps (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret);


/**
 * @ingroup crypto
 * Decapsulate a key for a private X25519 key.
 * Dual to #GNUNET_CRYPTO_hpke_authkem_encaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param skR secret key of receiver
 * @param pkS public key of the authenticating sender
 * @param c the encapsulated key
 * @param shared_secret where to write the key material
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_authkem_decaps (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkS,
  const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret);


/**
 * @ingroup crypto
 * Carries out ecdh encapsulation with given public key and the private key from a freshly created ephemeral key pair.
 * Following the terminology in https://eprint.iacr.org/2021/509.pdf.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param random_tweak random 8-bit value used as seed
 * @param pkR public key of receiver
 * @param c representative of ephemeral public key A to use for the ECDH (direct_map(r)=A=aG)
 * @param skE special elligator ephemeral private key from X25519 to use
 * @param shared_secret where to write the key material HKDF-Extract(r||aX)=HKDF-Extract(r||x(aG))
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_kem_encaps_norand (
  uint8_t random_tweak,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  const struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey *skE,
  struct GNUNET_ShortHashCode *shared_secret);

/**
 * @ingroup crypto
 * Carries out ecdh encapsulation with given public key and the private key from a freshly created ephemeral key pair.
 * Following the terminology in https://eprint.iacr.org/2021/509.pdf.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param pkR Receiver public key (X)
 * @param c representative of ephemeral public key A to use for the ECDH (direct_map(r)=A=aG)
 * @param shared_secret where to write the key material HKDF-Extract(r||aX)=HKDF-Extract(r||x(aG))
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_kem_encaps (
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret);

/**
 * @ingroup crypto
 * Carries out ecdh decapsulation with own private key and the representative of the received public key.
 * Following the terminology in https://eprint.iacr.org/2021/509.pdf.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param skR sender private key (x)
 * @param r received representative r, from which we can obtain the public key A (direct_map(r)=A=aG)
 * @param shared_secret where to write the key material HKDF-Extract(r||aX)=HKDF-Extract(r||x(aG))
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_kem_decaps (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret);

/**
 * @ingroup crypto
 * Decapsulate a key for a private X25519 key.
 * Elligator variant.
 * Dual to #GNUNET_CRYPTO_hpke_authkem_encaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param skR private key from X25519 to use for the ECDH (x)
 * @param pkS public key of the authenticating sender
 * @param c the encapsulated key
 * @param shared_secret where to write the key material
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_elligator_authkem_decaps (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkS,
  const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
  struct GNUNET_ShortHashCode *shared_secret);

/**
 * @ingroup crypto
 * Decapsulate a key for a private EdDSA key.
 * Dual to #GNUNET_CRRYPTO_eddsa_kem_encaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param priv private key from EdDSA to use for the ECDH (x)
 * @param c the encapsulated key
 * @param prk where to write the key material HKDF-Extract(c||aX)=HKDF-Extract(c||x(aG))
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_kem_decaps (const struct
                                GNUNET_CRYPTO_EddsaPrivateKey *priv,
                                const struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                                struct GNUNET_ShortHashCode *prk);

/**
 * @ingroup crypto
 * Encapsulate key material for a EdDSA public key.
 * Dual to #GNUNET_CRRYPTO_eddsa_kem_decaps.
 * Use #GNUNET_CRYPTO_hkdf_expand to derive further context-specific
 * keys from the key material.
 *
 * @param priv private key to use for the ECDH (y)
 * @param c public key from EdDSA to use for the ECDH (X=h(x)G)
 * @param prk where to write the key material HKDF-Extract(c||aX)=HKDF-Extract(c||x(aG))
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_kem_encaps (const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
                                struct GNUNET_CRYPTO_HpkeEncapsulation *c,
                                struct GNUNET_ShortHashCode *prk);


/**
 * RFC9180 HPKE encryption.
 * This sets the encryption context up for a sender of
 * encrypted messages.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be created and sent using "ctx"
 *
 * @param pkR the X25519 receiver public key
 * @param info the info context separator
 * @param info_len length of info in bytes
 * @param enc the encapsulation to exchange with the other party
 * @param ctx the encryption context allocated by caller
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_sender_setup (const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
                                 const uint8_t *info, size_t info_len,
                                 struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
                                 struct GNUNET_CRYPTO_HpkeContext *ctx);

/**
 * RFC9180 HPKE encryption.
 * This sets the encryption context up for a sender of
 * encrypted messages.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be created and sent using "ctx"
 *
 * @param kem the HPKE KEM to use
 * @param mode the HPKE mode
 * @param skE the X25519 ephemeral key to use as encapsulation
 * @param skR the X25519 sender private key (may be null for non-Auth modes)
 * @param info the info context separator
 * @param info_len length of info in bytes
 * @param psk the pre-shared key (must not be set non-PSK modes)
 * @param psk_len length of psk in bytes
 * @param psk_id the ID of the pre-shared key (must be set of psk is set)
 * @param psk_id_len length of psk_id in bytes
 * @param enc the encapsulation to exchange with the other party
 * @param ctx the encryption context allocated by caller
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_sender_setup2 (
  enum GNUNET_CRYPTO_HpkeKem kem,
  enum GNUNET_CRYPTO_HpkeMode mode,
  struct GNUNET_CRYPTO_EcdhePrivateKey *skE,
  struct GNUNET_CRYPTO_EcdhePrivateKey *skS,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
  const uint8_t *info, size_t info_len,
  const uint8_t *psk, size_t psk_len,
  const uint8_t *psk_id, size_t psk_id_len,
  struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  struct GNUNET_CRYPTO_HpkeContext *ctx);

/**
 * RFC9180 HPKE encryption.
 * This sets the encryption context up for a receiver of
 * encrypted messages.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be decrypted using "ctx"
 *
 * @param kem the HPKE KEM to use
 * @param mode the HPKE mode
 * @param enc the encapsulation from the sender
 * @param skR the X25519 receiver secret key
 * @param pkS the X25519 sender public key (may be NULL for non-Auth modes)
 * @param info the info context separator
 * @param info_len length of info in bytes
 * @param psk the pre-shared key (must not be set non-PSK modes)
 * @param psk_len length of psk in bytes
 * @param psk_id the ID of the pre-shared key (must be set of psk is set)
 * @param psk_id_len length of psk_id in bytes
 * @param ctx the encryption context allocated by caller
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_receiver_setup2 (
  enum GNUNET_CRYPTO_HpkeKem kem,
  enum GNUNET_CRYPTO_HpkeMode mode,
  const struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pkS,
  const uint8_t *info, size_t info_len,
  const uint8_t *psk, size_t psk_len,
  const uint8_t *psk_id, size_t psk_id_len,
  struct GNUNET_CRYPTO_HpkeContext *ctx);


/**
 * RFC9180 HPKE encryption.
 * This sets the encryption context up for a receiver of
 * encrypted messages.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be decrypted using "ctx"
 *
 * @param enc the encapsulation from the sender
 * @param skR the X25519 receiver secret key
 * @param info the info context separator
 * @param info_len length of info in bytes
 * @param ctx the encryption context allocated by caller
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_receiver_setup (
  const struct GNUNET_CRYPTO_HpkeEncapsulation *enc,
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const uint8_t *info,
  size_t info_len,
  struct GNUNET_CRYPTO_HpkeContext *ctx);

/**
 * RFC9180 HPKE encryption.
 * Encrypt messages in a context.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be decrypted using "ctx"
 *
 * @param ctx the encryption context
 * @param aad addition authenticated data to send (not encrypted)
 * @param aad_len length of aad in bytes
 * @param pt plaintext data to encrypt
 * @param pt_len length of pt in bytes
 * @param ct ciphertext to send (to be allocated by caller)
 * @param ct_len[out] length of written bytes in ct. may be NULL
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_seal (struct GNUNET_CRYPTO_HpkeContext *ctx,
                         const uint8_t *aad,
                         size_t aad_len,
                         const uint8_t *pt,
                         size_t pt_len,
                         uint8_t *ct,
                         unsigned long long *ct_len);


/**
 * RFC9180 HPKE encryption.
 * Encrypt messages in a context.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be decrypted using "ctx"
 *
 * @param pkR the X25519 receiver secret key
 * @param info the info context separator
 * @param info_len length of info in bytes
 * @param aad addition authenticated data to send (not encrypted)
 * @param aad_len length of aad in bytes
 * @param pt plaintext data to encrypt
 * @param pt_len length of pt in bytes
 * @param ct ciphertext to send (to be allocated by caller)
 * @param ct_len[out] length of written bytes in ct. may be NULL
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_seal_oneshot (const struct GNUNET_CRYPTO_EcdhePublicKey *pkR,
                                 const uint8_t *info, size_t info_len,
                                 const uint8_t*aad, size_t aad_len,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *ct, unsigned long long *ct_len);


/**
 * RFC9180 HPKE encryption.
 * Decrypt messages in a context.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be decrypted using "ctx"
 *
 * @param ctx the encryption context
 * @param aad addition authenticated data to send (not encrypted)
 * @param aad_len length of aad in bytes
 * @param ct ciphertext to decrypt
 * @param ct_len length of ct in bytes
 * @param pt plaintext (to be allocated by caller)
 * @param pt_len length of written bytes in pt. May be NULL
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_open (struct GNUNET_CRYPTO_HpkeContext *ctx,
                         const uint8_t*aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         uint8_t *pt, unsigned long long *pt_len_p);


/**
 * RFC9180 HPKE encryption.
 * Decrypt messages in a context.
 * Algorithm: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
 *
 * The encapsulation "enc" must be exchanged with the receiver.
 * From then on, encrypted messages can be decrypted using "ctx"
 *
 * @param skR the X25519 receiver secret key
 * @param info the info context separator
 * @param info_len length of info in bytes
 * @param aad addition authenticated data to send (not encrypted)
 * @param aad_len length of aad in bytes
 * @param ct ciphertext to decrypt
 * @param ct_len length of ct in bytes
 * @param pt plaintext (to be allocated by caller)
 * @param pt_len length of written bytes in pt. May be NULL
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_hpke_open_oneshot (
  const struct GNUNET_CRYPTO_EcdhePrivateKey *skR,
  const uint8_t *info, size_t info_len,
  const uint8_t*aad, size_t aad_len,
  const uint8_t *ct, size_t ct_len,
  uint8_t *pt, unsigned long long *pt_len);


/** HPKE END **/

/**
 * @ingroup crypto
 * Derive key material from a ECDH public key and a private ECDSA key.
 * Dual to #GNUNET_CRRYPTO_ecdh_ecdsa.
 *
 * @param priv private key from ECDSA to use for the ECDH (x)
 * @param pub public key to use for the ECDH (yG)
 * @param key_material where to write the key material H(h(x)yG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_ecdh (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                          struct GNUNET_HashCode *key_material);


/**
 * @ingroup crypto
 * Derive key material from a EdDSA public key and a private ECDH key.
 * Dual to #GNUNET_CRRYPTO_eddsa_ecdh.
 * This converts the Edwards25519 public key @a pub to a Curve25519
 * public key before computing a X25519 DH (see #GNUNET_CRYPTO_ecc_ecdh).
 * The resulting X25519 secret is then derived to a key using
 * SHA-512.
 * NOTE: Whenever you can get away with it, use separate key pairs
 * for signing and encryption (DH)!
 *
 * @param priv private key to use for the ECDH (y)
 * @param pub public key from EdDSA to use for the ECDH (X=h(x)G)
 * @param key_material where to write the key material H(yX)=H(h(x)yG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdh_eddsa (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                          const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
                          struct GNUNET_HashCode *key_material);


/**
 * @ingroup crypto
 * Derive key material from a EdDSA public key and a private ECDH key.
 * Dual to #GNUNET_CRRYPTO_x25519_ecdh.
 * NOTE: Whenever you can get away with it, use separate key pairs
 * for signing and encryption (DH)!
 *
 * @param priv private key to use for the ECDH (y)
 * @param pub public key from EdDSA to use for the ECDH (X=h(x)G)
 * @param dh the DH shared secret (NOTE: Derive key from this before use!)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdh_x25519 (const struct GNUNET_CRYPTO_EcdhePrivateKey *
                           priv,
                           const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                           struct GNUNET_CRYPTO_EcdhePublicKey *dh);

/**
 * @ingroup crypto
 * Derive key material from a EcDSA public key and a private ECDH key.
 * Dual to #GNUNET_CRRYPTO_ecdsa_ecdh.
 *
 * @param priv private key to use for the ECDH (y)
 * @param pub public key from ECDSA to use for the ECDH (X=h(x)G)
 * @param key_material where to write the key material H(yX)=H(h(x)yG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdh_ecdsa (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
                          struct GNUNET_HashCode *key_material);


/**
 * @ingroup crypto
 * @brief EdDSA sign a given block.
 *
 * The @a purpose data is the beginning of the data of which the signature is
 * to be created. The `size` field in @a purpose must correctly indicate the
 * number of bytes of the data structure, including its header.  If possible,
 * use #GNUNET_CRYPTO_eddsa_sign() instead of this function (only if @a validate
 * is not fixed-size, you must use this function directly).
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param[out] sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_sign_ (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EddsaSignature *sig);


/**
 * @ingroup crypto
 * @brief EdDSA sign a given block.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param[out] sig where to write the signature
 */
#define GNUNET_CRYPTO_eddsa_sign(priv,ps,sig) do {                 \
    /* check size is set correctly */                              \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*ps));    \
    /* check 'ps' begins with the purpose */                       \
    GNUNET_static_assert (((void*) (ps)) ==                        \
                          ((void*) &(ps)->purpose));               \
    GNUNET_assert (GNUNET_OK ==                                    \
                   GNUNET_CRYPTO_eddsa_sign_ (priv,                \
                                              &(ps)->purpose,      \
                                              sig));               \
} while (0)


/**
 * @ingroup crypto
 * @brief ECDSA Sign a given block.
 *
 * The @a purpose data is the beginning of the data of which the signature is
 * to be created. The `size` field in @a purpose must correctly indicate the
 * number of bytes of the data structure, including its header. If possible,
 * use #GNUNET_CRYPTO_ecdsa_sign() instead of this function (only if @a validate
 * is not fixed-size, you must use this function directly).
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param[out] sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_sign_ (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EcdsaSignature *sig);

/**
 * @brief
 *
 * @param priv
 * @param data
 * @param size
 * @param sig
 * @return enum GNUNET_GenericReturnValue
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_sign_raw (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  void *data,
  size_t size,
  struct GNUNET_CRYPTO_EddsaSignature *sig);

/**
 * @ingroup crypto
 * @brief ECDSA sign a given block.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param[out] sig where to write the signature
 */
#define GNUNET_CRYPTO_ecdsa_sign(priv,ps,sig) do {                 \
    /* check size is set correctly */                              \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));  \
    /* check 'ps' begins with the purpose */                       \
    GNUNET_static_assert (((void*) (ps)) ==                        \
                          ((void*) &(ps)->purpose));               \
    GNUNET_assert (GNUNET_OK ==                                    \
                   GNUNET_CRYPTO_ecdsa_sign_ (priv,                \
                                              &(ps)->purpose,      \
                                              sig));               \
} while (0)

/**
 * @ingroup crypto
 * @brief Edx25519 sign a given block.
 *
 * The @a purpose data is the beginning of the data of which the signature is
 * to be created. The `size` field in @a purpose must correctly indicate the
 * number of bytes of the data structure, including its header.  If possible,
 * use #GNUNET_CRYPTO_edx25519_sign() instead of this function (only if @a
 * validate is not fixed-size, you must use this function directly).
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param[out] sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_edx25519_sign_ (
  const struct GNUNET_CRYPTO_Edx25519PrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_Edx25519Signature *sig);


/**
 * @ingroup crypto
 * @brief Edx25519 sign a given block.  The resulting signature is compatible
 * with EdDSA.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param[out] sig where to write the signature
 */
#define GNUNET_CRYPTO_edx25519_sign(priv,ps,sig) do {              \
    /* check size is set correctly */                              \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));  \
    /* check 'ps' begins with the purpose */                       \
    GNUNET_static_assert (((void*) (ps)) ==                        \
                          ((void*) &(ps)->purpose));               \
    GNUNET_assert (GNUNET_OK ==                                    \
                   GNUNET_CRYPTO_edx25519_sign_ (priv,             \
                                                 &(ps)->purpose,   \
                                                 sig));            \
} while (0)


/**
 * @ingroup crypto
 * @brief Verify EdDSA signature.
 *
 * The @a validate data is the beginning of the data of which the signature
 * is to be verified. The `size` field in @a validate must correctly indicate
 * the number of bytes of the data structure, including its header.  If @a
 * purpose does not match the purpose given in @a validate (the latter must be
 * in big endian), signature verification fails.  If possible,
 * use #GNUNET_CRYPTO_eddsa_verify() instead of this function (only if @a validate
 * is not fixed-size, you must use this function directly).
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_verify_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const struct GNUNET_CRYPTO_EddsaSignature *sig,
  const struct GNUNET_CRYPTO_EddsaPublicKey *pub);


/**
 * @ingroup crypto
 * @brief Verify EdDSA signature.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param purp purpose of the signature, must match 'ps->purpose.purpose'
 *              (except in host byte order)
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param sig where to write the signature
 */
#define GNUNET_CRYPTO_eddsa_verify(purp,ps,sig,pub) ({             \
    /* check size is set correctly */                              \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));  \
    /* check 'ps' begins with the purpose */                       \
    GNUNET_static_assert (((void*) (ps)) ==                        \
                          ((void*) &(ps)->purpose));               \
    GNUNET_CRYPTO_eddsa_verify_ (purp,                             \
                                 &(ps)->purpose,                   \
                                 sig,                              \
                                 pub);                             \
  })

/**
 * @ingroup crypto
 * @brief Verify ECDSA signature.
 *
 * The @a validate data is the beginning of the data of which the signature is
 * to be verified. The `size` field in @a validate must correctly indicate the
 * number of bytes of the data structure, including its header.  If @a purpose
 * does not match the purpose given in @a validate (the latter must be in big
 * endian), signature verification fails.  If possible, use
 * #GNUNET_CRYPTO_eddsa_verify() instead of this function (only if @a validate
 * is not fixed-size, you must use this function directly).
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_verify_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const struct GNUNET_CRYPTO_EcdsaSignature *sig,
  const struct GNUNET_CRYPTO_EcdsaPublicKey *pub);


/**
 * @ingroup crypto
 * @brief Verify ECDSA signature.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param purp purpose of the signature, must match 'ps->purpose.purpose'
 *              (except in host byte order)
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param sig where to write the signature
 */
#define GNUNET_CRYPTO_ecdsa_verify(purp,ps,sig,pub) ({             \
    /* check size is set correctly */                              \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));  \
    /* check 'ps' begins with the purpose */                       \
    GNUNET_static_assert (((void*) (ps)) ==                        \
                          ((void*) &(ps)->purpose));               \
    GNUNET_CRYPTO_ecdsa_verify_ (purp,                             \
                                 &(ps)->purpose,                   \
                                 sig,                              \
                                 pub);                             \
  })

/**
 * @ingroup crypto
 * @brief Verify Edx25519 signature.
 *
 * The @a validate data is the beginning of the data of which the signature
 * is to be verified. The `size` field in @a validate must correctly indicate
 * the number of bytes of the data structure, including its header.  If @a
 * purpose does not match the purpose given in @a validate (the latter must be
 * in big endian), signature verification fails.  If possible, use
 * #GNUNET_CRYPTO_edx25519_verify() instead of this function (only if @a
 * validate is not fixed-size, you must use this function directly).
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_edx25519_verify_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const struct GNUNET_CRYPTO_Edx25519Signature *sig,
  const struct GNUNET_CRYPTO_Edx25519PublicKey *pub);


/**
 * @ingroup crypto
 * @brief Verify Edx25519 signature.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param purp purpose of the signature, must match 'ps->purpose.purpose'
 *              (except in host byte order)
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param sig where to write the signature
 */
#define GNUNET_CRYPTO_edx25519_verify(purp,ps,sig,pub) ({         \
    /* check size is set correctly */                             \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps))); \
    /* check 'ps' begins with the purpose */                      \
    GNUNET_static_assert (((void*) (ps)) ==                       \
                          ((void*) &(ps)->purpose));              \
    GNUNET_CRYPTO_edx25519_verify_ (purp,                         \
                                    &(ps)->purpose,               \
                                    sig,                          \
                                    pub);                         \
  })

/**
 * @ingroup crypto
 * Derive a private key from a given private key and a label.
 * Essentially calculates a private key 'h = H(l,P) * d mod n'
 * where n is the size of the ECC group and P is the public
 * key associated with the private key 'd'.
 *
 * @param priv original private key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @return derived private key
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_private_key_derive (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  const char *label,
  const char *context);


/**
 * @ingroup crypto
 * Derive a public key from a given public key and a label.
 * Essentially calculates a public key 'V = H(l,P) * P'.
 *
 * @param pub original public key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h'.
 *        typically the name of the subsystem/application
 * @param result where to write the derived public key
 */
void
GNUNET_CRYPTO_ecdsa_public_key_derive (
  const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
  const char *label,
  const char *context,
  struct GNUNET_CRYPTO_EcdsaPublicKey *result);

/**
 * This is a signature function for ECDSA which takes a
 * private key, derives/blinds it and signs the message.
 *
 * @param pkey original private key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @param purpose the signature purpose
 * @param sig the resulting signature
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_sign_derived (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
  const char *label,
  const char *context,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EcdsaSignature *sig);


/**
 * @ingroup crypto
 * Derive a private scalar from a given private key and a label.
 * Essentially calculates a private key 'h = H(l,P) * d mod n'
 * where n is the size of the ECC group and P is the public
 * key associated with the private key 'd'.
 * The result is the derived private _scalar_, not the private
 * key as for EdDSA we cannot derive before we hash the
 * private key.
 *
 * @param priv original private key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @param result derived private scalar
 */
void
GNUNET_CRYPTO_eddsa_private_key_derive (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  const char *label,
  const char *context,
  struct GNUNET_CRYPTO_EddsaPrivateScalar *result);


/**
 * @ingroup crypto
 * Derive a public key from a given public key and a label.
 * Essentially calculates a public key 'V = H(l,P) * P'.
 *
 * @param pub original public key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h'.
 *        typically the name of the subsystem/application
 * @param result where to write the derived public key
 */
void
GNUNET_CRYPTO_eddsa_public_key_derive (
  const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
  const char *label,
  const char *context,
  struct GNUNET_CRYPTO_EddsaPublicKey *result);


/**
 * This is a signature function for EdDSA which takes a
 * private key and derives it using the label and context
 * before signing.
 *
 * @param pkey original private key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @param purpose the signature purpose
 * @param sig the resulting signature
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_sign_derived (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *pkey,
  const char *label,
  const char *context,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EddsaSignature *sig);


/**
 * Extract the public key of the given private scalar.
 *
 * @param s the private scalar
 * @param pkey the resulting public key
 */
void
GNUNET_CRYPTO_eddsa_key_get_public_from_scalar (
  const struct GNUNET_CRYPTO_EddsaPrivateScalar *s,
  struct GNUNET_CRYPTO_EddsaPublicKey *pkey);

/**
 * @ingroup crypto
 * Derive a private scalar from a given private key and a label.
 * Essentially calculates a private key 'h = H(l,P) * d mod n'
 * where n is the size of the ECC group and P is the public
 * key associated with the private key 'd'.
 *
 * @param priv original private key
 * @param seed input seed
 * @param seedsize size of the seed
 * @param result derived private key
 */
void
GNUNET_CRYPTO_edx25519_private_key_derive (
  const struct GNUNET_CRYPTO_Edx25519PrivateKey *priv,
  const void *seed,
  size_t seedsize,
  struct GNUNET_CRYPTO_Edx25519PrivateKey *result);


/**
 * @ingroup crypto
 * Derive a public key from a given public key and a label.
 * Essentially calculates a public key 'V = H(l,P) * P'.
 *
 * @param pub original public key
 * @param seed input seed
 * @param seedsize size of the seed
 * @param result where to write the derived public key
 */
void
GNUNET_CRYPTO_edx25519_public_key_derive (
  const struct GNUNET_CRYPTO_Edx25519PublicKey *pub,
  const void *seed,
  size_t seedsize,
  struct GNUNET_CRYPTO_Edx25519PublicKey *result);


/**
 * @ingroup crypto
 * Clears the most significant bit and second most significant bit of the serialized representaive before applying elligator direct map.
 *
 * @param representative serialized elligator representative of an element of Curves25519's finite field
 * @param point destination for the calculated point on the curve
 * @param high_y bool pointed to will be set to 'true' if corresponding y-coordinate is > 2 ^ 254 - 10, otherwise 0. Can be set to NULL if not needed.
 */
void
GNUNET_CRYPTO_ecdhe_elligator_decoding (
  struct GNUNET_CRYPTO_EcdhePublicKey *point,
  bool *high_y,
  const struct GNUNET_CRYPTO_ElligatorRepresentative *representative);


/**
 * @ingroup crypto
 * Encodes a point on Curve25519 to a an element of the underlying finite field.
 * This transformation is deterministic.
 *
 * @param random_tweak random 8-bit value used as seed
 * @param r storage for the calculated representative
 * @param pub a point on the curve
 * @return 'true' if the given point can be encoded into a representative. Otherwise 'false' is returned and the content of the representative storage is undefined
 */
bool
GNUNET_CRYPTO_ecdhe_elligator_encoding (
  uint8_t random_tweak,
  struct GNUNET_CRYPTO_ElligatorRepresentative *r,
  const struct GNUNET_CRYPTO_EcdhePublicKey *pub);


/**
 * @ingroup crypto
 * Generates a valid public key for elligator's inverse map by adding a lower order point to a prime order point.
 * Following Method 1 in description https://elligator.org/key-exchange section Step 2: Generate a “special” public key.
 *
 * @param random_tweak random 8-bit value used as seed
 * @param sk private key for generating valid public key
 * @param pub valid public key for elligator inverse map
 * @param repr storage for a calculated representative
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdhe_elligator_key_get_public_norand (
  uint8_t random_tweak,
  const struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey *sk,
  struct GNUNET_CRYPTO_EcdhePublicKey *pub,
  struct GNUNET_CRYPTO_ElligatorRepresentative *repr);

/**
 * @ingroup crypto
 * Generates a valid public key for elligator's inverse map by adding a lower order point to a prime order point.
 * Following Method 1 in description https://elligator.org/key-exchange section Step 2: Generate a “special” public key.
 *
 * @param sk private key for generating valid public key
 * @param pub valid public key for elligator inverse map
 * @param repr storage for a calculated representative
 * @return GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdhe_elligator_key_get_public (
  const struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey *sk,
  struct GNUNET_CRYPTO_EcdhePublicKey *pub,
  struct GNUNET_CRYPTO_ElligatorRepresentative *repr);


/**
 * @ingroup crypto
 * Generates a private key for Curve25519.
 *
 * @param sk Curve25519 private key
 */
void
GNUNET_CRYPTO_ecdhe_elligator_key_create (
  struct GNUNET_CRYPTO_ElligatorEcdhePrivateKey *sk);


/**
 * Output the given MPI value to the given buffer in network
 * byte order.  The MPI @a val may not be negative.
 *
 * @param buf where to output to
 * @param size number of bytes in @a buf
 * @param val value to write to @a buf
 */
void
GNUNET_CRYPTO_mpi_print_unsigned (void *buf,
                                  size_t size,
                                  gcry_mpi_t val);


/**
 * Convert data buffer into MPI value.
 * The buffer is interpreted as network
 * byte order, unsigned integer.
 *
 * @param result where to store MPI value (allocated)
 * @param data raw data (GCRYMPI_FMT_USG)
 * @param size number of bytes in @a data
 */
void
GNUNET_CRYPTO_mpi_scan_unsigned (gcry_mpi_t *result,
                                 const void *data,
                                 size_t size);


/**
 * Create a freshly generated paillier public key.
 *
 * @param[out] public_key Where to store the public key?
 * @param[out] private_key Where to store the private key?
 */
void
GNUNET_CRYPTO_paillier_create (
  struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
  struct GNUNET_CRYPTO_PaillierPrivateKey *private_key);


/**
 * Encrypt a plaintext with a paillier public key.
 *
 * @param public_key Public key to use.
 * @param m Plaintext to encrypt.
 * @param desired_ops How many homomorphic ops the caller intends to use
 * @param[out] ciphertext Encryption of @a plaintext with @a public_key.
 * @return guaranteed number of supported homomorphic operations >= 1,
 *         or desired_ops, in case that is lower,
 *         or -1 if less than one homomorphic operation is possible
 */
int
GNUNET_CRYPTO_paillier_encrypt (
  const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
  const gcry_mpi_t m,
  int desired_ops,
  struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext);


/**
 * Decrypt a paillier ciphertext with a private key.
 *
 * @param private_key Private key to use for decryption.
 * @param public_key Public key to use for decryption.
 * @param ciphertext Ciphertext to decrypt.
 * @param[out] m Decryption of @a ciphertext with @a private_key.
 */
void
GNUNET_CRYPTO_paillier_decrypt (
  const struct GNUNET_CRYPTO_PaillierPrivateKey *private_key,
  const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
  const struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext,
  gcry_mpi_t m);


/**
 * Compute a ciphertext that represents the sum of the plaintext in @a c1
 * and @a c2
 *
 * Note that this operation can only be done a finite number of times
 * before an overflow occurs.
 *
 * @param public_key Public key to use for encryption.
 * @param c1 Paillier cipher text.
 * @param c2 Paillier cipher text.
 * @param[out] result Result of the homomorphic operation.
 * @return #GNUNET_OK if the result could be computed,
 *         #GNUNET_SYSERR if no more homomorphic operations are remaining.
 */
int
GNUNET_CRYPTO_paillier_hom_add (
  const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
  const struct GNUNET_CRYPTO_PaillierCiphertext *c1,
  const struct GNUNET_CRYPTO_PaillierCiphertext *c2,
  struct GNUNET_CRYPTO_PaillierCiphertext *result);


/**
 * Get the number of remaining supported homomorphic operations.
 *
 * @param c Paillier cipher text.
 * @return the number of remaining homomorphic operations
 */
int
GNUNET_CRYPTO_paillier_hom_get_remaining (
  const struct GNUNET_CRYPTO_PaillierCiphertext *c);


/* ********* Chaum-style RSA-based blind signatures ******************* */


/**
 * The private information of an RSA key pair.
 */
struct GNUNET_CRYPTO_RsaPrivateKey;

/**
 * The public information of an RSA key pair.
 */
struct GNUNET_CRYPTO_RsaPublicKey;

/**
 * Constant-size pre-secret for blinding key generation.
 */
struct GNUNET_CRYPTO_RsaBlindingKeySecret
{
  /**
   * Bits used to generate the blinding key.  256 bits
   * of entropy is enough.
   */
  uint32_t pre_secret[8] GNUNET_PACKED;
};

/**
 * @brief an RSA signature
 */
struct GNUNET_CRYPTO_RsaSignature;


/**
 * Create a new private key. Caller must free return value.
 *
 * @param len length of the key in bits (e.g. 2048)
 * @return fresh private key
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_private_key_create (unsigned int len);


/**
 * Free memory occupied by the private key.
 *
 * @param key pointer to the memory to free
 */
void
GNUNET_CRYPTO_rsa_private_key_free (struct GNUNET_CRYPTO_RsaPrivateKey *key);


/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 *
 * @param key the private key
 * @param[out] buffer set to a buffer with the encoded key
 * @return size of memory allocatedin @a buffer
 */
size_t
GNUNET_CRYPTO_rsa_private_key_encode (
  const struct GNUNET_CRYPTO_RsaPrivateKey *key,
  void **buffer);


/**
 * Decode the private key from the data-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the private key data is stored
 * @param buf_size the size of the data in @a buf
 * @return NULL on error
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_private_key_decode (const void *buf,
                                      size_t buf_size);


/**
 * Duplicate the given private key
 *
 * @param key the private key to duplicate
 * @return the duplicate key; NULL upon error
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_private_key_dup (
  const struct GNUNET_CRYPTO_RsaPrivateKey *key);


/**
 * Extract the public key of the given private key.
 *
 * @param priv the private key
 * @return NULL on error, otherwise the public key
 */
struct GNUNET_CRYPTO_RsaPublicKey *
GNUNET_CRYPTO_rsa_private_key_get_public (
  const struct GNUNET_CRYPTO_RsaPrivateKey *priv);


/**
 * Compute hash over the public key.
 *
 * @param key public key to hash
 * @param hc where to store the hash code
 */
void
GNUNET_CRYPTO_rsa_public_key_hash (
  const struct GNUNET_CRYPTO_RsaPublicKey *key,
  struct GNUNET_HashCode *hc);


/**
 * Check if @a key is well-formed.
 *
 * @return true if @a key is well-formed.
 */
bool
GNUNET_CRYPTO_rsa_public_key_check (
  const struct GNUNET_CRYPTO_RsaPublicKey *key);

/**
 * Obtain the length of the RSA key in bits.
 *
 * @param key the public key to introspect
 * @return length of the key in bits
 */
unsigned int
GNUNET_CRYPTO_rsa_public_key_len (const struct GNUNET_CRYPTO_RsaPublicKey *key);


/**
 * Free memory occupied by the public key.
 *
 * @param key pointer to the memory to free
 */
void
GNUNET_CRYPTO_rsa_public_key_free (struct GNUNET_CRYPTO_RsaPublicKey *key);


/**
 * Encode the public key in a format suitable for
 * storing it into a file.
 *
 * @param key the private key
 * @param[out] buffer set to a buffer with the encoded key
 * @return size of memory allocated in @a buffer
 */
size_t
GNUNET_CRYPTO_rsa_public_key_encode (
  const struct GNUNET_CRYPTO_RsaPublicKey *key,
  void **buffer);


/**
 * Decode the public key from the data-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the public key data is stored
 * @param len the length of the data in @a buf
 * @return NULL on error
 */
struct GNUNET_CRYPTO_RsaPublicKey *
GNUNET_CRYPTO_rsa_public_key_decode (const char *buf,
                                     size_t len);


/**
 * Duplicate the given public key
 *
 * @param key the public key to duplicate
 * @return the duplicate key; NULL upon error
 */
struct GNUNET_CRYPTO_RsaPublicKey *
GNUNET_CRYPTO_rsa_public_key_dup (const struct GNUNET_CRYPTO_RsaPublicKey *key);


/**
 * Compare the values of two signatures.
 *
 * @param s1 one signature
 * @param s2 the other signature
 * @return 0 if the two are equal
 */
int
GNUNET_CRYPTO_rsa_signature_cmp (const struct GNUNET_CRYPTO_RsaSignature *s1,
                                 const struct GNUNET_CRYPTO_RsaSignature *s2);

/**
 * Compare the values of two private keys.
 *
 * @param p1 one private key
 * @param p2 the other private key
 * @return 0 if the two are equal
 */
int
GNUNET_CRYPTO_rsa_private_key_cmp (
  const struct GNUNET_CRYPTO_RsaPrivateKey *p1,
  const struct GNUNET_CRYPTO_RsaPrivateKey *p2);


/**
 * Compare the values of two public keys.
 *
 * @param p1 one public key
 * @param p2 the other public key
 * @return 0 if the two are equal
 */
int
GNUNET_CRYPTO_rsa_public_key_cmp (const struct GNUNET_CRYPTO_RsaPublicKey *p1,
                                  const struct GNUNET_CRYPTO_RsaPublicKey *p2);


/**
 * @brief RSA Parameters to create blinded signature
 */
struct GNUNET_CRYPTO_RsaBlindedMessage
{
  /**
   * Blinded message to be signed
   * Note: is malloc()'ed!
   */
  void *blinded_msg;

  /**
   * Size of the @e blinded_msg to be signed.
   */
  size_t blinded_msg_size;
};


/**
 * Blinds the given message with the given blinding key
 *
 * @param message the message to sign
 * @param message_size number of bytes in @a message
 * @param bks the blinding key
 * @param pkey the public key of the signer
 * @param[out] bm set to the blinded message
 * @return #GNUNET_YES if successful, #GNUNET_NO if RSA key is malicious
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_rsa_blind (const void *message,
                         size_t message_size,
                         const struct GNUNET_CRYPTO_RsaBlindingKeySecret *bks,
                         struct GNUNET_CRYPTO_RsaPublicKey *pkey,
                         struct GNUNET_CRYPTO_RsaBlindedMessage *bm);


/**
 * Sign a blinded value, which must be a full domain hash of a message.
 *
 * @param key private key to use for the signing
 * @param bm the (blinded) message to sign
 * @return NULL on error, signature on success
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_sign_blinded (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                                const struct
                                GNUNET_CRYPTO_RsaBlindedMessage *bm);


/**
 * Create and sign a full domain hash of a message.
 *
 * @param key private key to use for the signing
 * @param message the message to sign
 * @param message_size number of bytes in @a message
 * @return NULL on error, including a malicious RSA key, signature on success
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_sign_fdh (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                            const void *message,
                            size_t message_size);


/**
 * Free memory occupied by blinded message. Only frees contents, not
 * @a bm itself.
 *
 * @param[in] bm memory to free
 */
void
GNUNET_CRYPTO_rsa_blinded_message_free (
  struct GNUNET_CRYPTO_RsaBlindedMessage *bm);


/**
 * Free memory occupied by signature.
 *
 * @param[in] sig memory to free
 */
void
GNUNET_CRYPTO_rsa_signature_free (struct GNUNET_CRYPTO_RsaSignature *sig);


/**
 * Encode the given signature in a format suitable for storing it into a file.
 *
 * @param sig the signature
 * @param[out] buffer set to a buffer with the encoded key
 * @return size of memory allocated in @a buffer
 */
size_t
GNUNET_CRYPTO_rsa_signature_encode (
  const struct GNUNET_CRYPTO_RsaSignature *sig,
  void **buffer);


/**
 * Decode the signature from the data-format back to the "normal", internal
 * format.
 *
 * @param buf the buffer where the public key data is stored
 * @param buf_size the number of bytes of the data in @a buf
 * @return NULL on error
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_signature_decode (
  const void *buf,
  size_t buf_size);


/**
 * Duplicate the given rsa signature
 *
 * @param sig the signature to duplicate
 * @return the duplicate key; NULL upon error
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_signature_dup (
  const struct GNUNET_CRYPTO_RsaSignature *sig);


/**
 * Unblind a blind-signed signature.  The signature should have been generated
 * with #GNUNET_CRYPTO_rsa_sign() using a hash that was blinded with
 * #GNUNET_CRYPTO_rsa_blind().
 *
 * @param sig the signature made on the blinded signature purpose
 * @param bks the blinding key secret used to blind the signature purpose
 * @param pkey the public key of the signer
 * @return unblinded signature on success, NULL if RSA key is bad or malicious.
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_unblind (const struct GNUNET_CRYPTO_RsaSignature *sig,
                           const struct GNUNET_CRYPTO_RsaBlindingKeySecret *bks,
                           struct GNUNET_CRYPTO_RsaPublicKey *pkey);


/**
 * Verify whether the given hash corresponds to the given signature and the
 * signature is valid with respect to the given public key.
 *
 * @param message the message to sign
 * @param message_size number of bytes in @a message
 * @param sig signature that is being validated
 * @param public_key public key of the signer
 * @returns #GNUNET_YES if ok, #GNUNET_NO if RSA key is malicious, #GNUNET_SYSERR if signature
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_rsa_verify (const void *message,
                          size_t message_size,
                          const struct GNUNET_CRYPTO_RsaSignature *sig,
                          const struct GNUNET_CRYPTO_RsaPublicKey *public_key);


/**
 * Create a new random private key.
 *
 * @param[out] priv where to write the fresh private key
 */
void
GNUNET_CRYPTO_cs_private_key_generate (struct GNUNET_CRYPTO_CsPrivateKey *priv);


/**
 * Extract the public key of the given private key.
 *
 * @param priv the private key
 * @param[out] pub where to write the public key
 */
void
GNUNET_CRYPTO_cs_private_key_get_public (
  const struct GNUNET_CRYPTO_CsPrivateKey *priv,
  struct GNUNET_CRYPTO_CsPublicKey *pub);


/**
 * Derive a new secret r pair r0 and r1.
 * In original papers r is generated randomly
 * To provide abort-idempotency, r needs to be derived but still needs to be UNPREDICTABLE
 * To ensure unpredictability a new nonce should be used when a new r needs to be derived.
 * Uses HKDF internally.
 * Comment: Can be done in one HKDF shot and split output.
 *
 * @param nonce is a random nonce
 * @param seed seed to use in derivation
 * @param lts is a long-term-secret in form of a private key
 * @param[out] r array containing derived secrets r0 and r1
 */
void
GNUNET_CRYPTO_cs_r_derive (
  const struct GNUNET_CRYPTO_CsSessionNonce *nonce,
  const char *seed,
  const struct GNUNET_CRYPTO_CsPrivateKey *lts,
  struct GNUNET_CRYPTO_CsRSecret r[2]);


/**
 * Extract the public R of the given secret r.
 *
 * @param r_priv the private key
 * @param[out] r_pub where to write the public key
 */
void
GNUNET_CRYPTO_cs_r_get_public (
  const struct GNUNET_CRYPTO_CsRSecret *r_priv,
  struct GNUNET_CRYPTO_CsRPublic *r_pub);


/**
 * Derives new random blinding factors.
 * In original papers blinding factors are generated randomly
 * To provide abort-idempotency, blinding factors need to be derived but still need to be UNPREDICTABLE.
 * To ensure unpredictability a new nonce has to be used.
 * Uses HKDF internally.
 *
 * @param blind_seed is the blinding seed to derive blinding factors
 * @param[out] bs array containing the two derived blinding secrets
 */
void
GNUNET_CRYPTO_cs_blinding_secrets_derive (
  const struct GNUNET_CRYPTO_CsBlindingNonce *blind_seed,
  struct GNUNET_CRYPTO_CsBlindingSecret bs[2]);


/**
 * @brief CS Parameters derived from the message
 * during blinding to create blinded signature
 */
struct GNUNET_CRYPTO_CsBlindedMessage
{
  /**
   * The Clause Schnorr c_0 and c_1 containing the blinded message
   */
  struct GNUNET_CRYPTO_CsC c[2];

  /**
   * Nonce used in initial request.
   */
  struct GNUNET_CRYPTO_CsSessionNonce nonce;

};


/**
 * Pair of Public R values for Cs denominations
 */
struct GNUNET_CRYPTO_CSPublicRPairP
{
  struct GNUNET_CRYPTO_CsRPublic r_pub[2];
};


/**
 * Calculate two blinded c's.
 * Comment: One would be insecure due to Wagner's algorithm solving ROS
 *
 * @param bs array of the two blinding factor structs each containing alpha and beta
 * @param r_pub array of the two signer's nonce R
 * @param pub the public key of the signer
 * @param msg the message to blind in preparation for signing
 * @param msg_len length of message msg
 * @param[out] blinded_c array of the two blinded c's
 * @param[out] r_pub_blind array of the two blinded R
 */
void
GNUNET_CRYPTO_cs_calc_blinded_c (
  const struct GNUNET_CRYPTO_CsBlindingSecret bs[2],
  const struct GNUNET_CRYPTO_CsRPublic r_pub[2],
  const struct GNUNET_CRYPTO_CsPublicKey *pub,
  const void *msg,
  size_t msg_len,
  struct GNUNET_CRYPTO_CsC blinded_c[2],
  struct GNUNET_CRYPTO_CSPublicRPairP *r_pub_blind);


/**
 * The Sign Answer for Clause Blind Schnorr signature.
 * The sign operation returns a parameter @param b and the signature
 * scalar @param s_scalar.
 */
struct GNUNET_CRYPTO_CsBlindSignature
{
  /**
   * To make ROS problem harder, the signer chooses an unpredictable b and
   * only calculates signature of c_b
   */
  unsigned int b;

  /**
   * The blinded s scalar calculated from c_b
   */
  struct GNUNET_CRYPTO_CsBlindS s_scalar;
};


/**
 * Sign a blinded @a c.
 * This function derives b from a nonce and a longterm secret.
 * In the original papers b is generated randomly.
 * To provide abort-idempotency, b needs to be derived but still need to be UNPREDICTABLE.
 * To ensure unpredictability a new nonce has to be used for every signature.
 * HKDF is used internally for derivation.
 * r0 and r1 can be derived prior by using GNUNET_CRYPTO_cs_r_derive.
 *
 * @param priv private key to use for the signing and as LTS in HKDF
 * @param r array of the two secret inputs from the signer
 * @param bm blinded message, including array of the two blinded c to sign c_b and the random nonce
 * @param[out] cs_blind_sig where to write the blind signature
 */
void
GNUNET_CRYPTO_cs_sign_derive (
  const struct GNUNET_CRYPTO_CsPrivateKey *priv,
  const struct GNUNET_CRYPTO_CsRSecret r[2],
  const struct GNUNET_CRYPTO_CsBlindedMessage *bm,
  struct GNUNET_CRYPTO_CsBlindSignature *cs_blind_sig);


/**
 * Unblind a blind-signed signature using a c that was blinded
 *
 * @param blinded_signature_scalar the signature made on the blinded c
 * @param bs the blinding factors used in the blinding
 * @param[out] signature_scalar where to write the unblinded signature
 */
void
GNUNET_CRYPTO_cs_unblind (
  const struct GNUNET_CRYPTO_CsBlindS *blinded_signature_scalar,
  const struct GNUNET_CRYPTO_CsBlindingSecret *bs,
  struct GNUNET_CRYPTO_CsS *signature_scalar);


/**
 * Verify whether the given message corresponds to the given signature and the
 * signature is valid with respect to the given public key.
 *
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @param msg is the message that should be signed by @a sig  (message is used to calculate c)
 * @param msg_len is the message length
 * @returns #GNUNET_YES on success, #GNUNET_SYSERR if signature invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_cs_verify (
  const struct GNUNET_CRYPTO_CsSignature *sig,
  const struct GNUNET_CRYPTO_CsPublicKey *pub,
  const void *msg,
  size_t msg_len);


/**
 * Types of public keys used for blind signatures.
 */
enum GNUNET_CRYPTO_BlindSignatureAlgorithm
{

  /**
   * Invalid type of signature.
   */
  GNUNET_CRYPTO_BSA_INVALID = 0,

  /**
   * RSA blind signature.
   */
  GNUNET_CRYPTO_BSA_RSA = 1,

  /**
   * Clause Blind Schnorr signature.
   */
  GNUNET_CRYPTO_BSA_CS = 2
};


/**
 * @brief Type of (unblinded) signatures.
 */
struct GNUNET_CRYPTO_UnblindedSignature
{

  /**
   * Type of the signature.
   */
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Details, depending on @e cipher.
   */
  union
  {
    /**
     * If we use #GNUNET_CRYPTO_BSA_CS in @a cipher.
     */
    struct GNUNET_CRYPTO_CsSignature cs_signature;

    /**
     * If we use #GNUNET_CRYPTO_BSA_RSA in @a cipher.
     */
    struct GNUNET_CRYPTO_RsaSignature *rsa_signature;

  } details;

};


/**
 * @brief Type for *blinded* signatures.
 * Must be unblinded before it becomes valid.
 */
struct GNUNET_CRYPTO_BlindedSignature
{

  /**
   * Type of the signature.
   */
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Details, depending on @e cipher.
   */
  union
  {
    /**
     * If we use #GNUNET_CRYPTO_BSA_CS in @a cipher.
     * At this point only the blinded s scalar is used.
     * The final signature consisting of r,s is built after unblinding.
     */
    struct GNUNET_CRYPTO_CsBlindSignature blinded_cs_answer;

    /**
     * If we use #GNUNET_CRYPTO_BSA_RSA in @a cipher.
     */
    struct GNUNET_CRYPTO_RsaSignature *blinded_rsa_signature;

  } details;

};


/**
 * @brief Type of public signing keys for blind signatures.
 */
struct GNUNET_CRYPTO_BlindSignPublicKey
{

  /**
   * Type of the public key.
   */
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Hash of the public key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Details, depending on @e cipher.
   */
  union
  {
    /**
     * If we use #GNUNET_CRYPTO_BSA_CS in @a cipher.
     */
    struct GNUNET_CRYPTO_CsPublicKey cs_public_key;

    /**
     * If we use #GNUNET_CRYPTO_BSA_RSA in @a cipher.
     */
    struct GNUNET_CRYPTO_RsaPublicKey *rsa_public_key;

  } details;
};


/**
 * @brief Type of private signing keys for blind signing.
 */
struct GNUNET_CRYPTO_BlindSignPrivateKey
{

  /**
   * Type of the public key.
   */
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Details, depending on @e cipher.
   */
  union
  {
    /**
     * If we use #GNUNET_CRYPTO_BSA_CS in @a cipher.
     */
    struct GNUNET_CRYPTO_CsPrivateKey cs_private_key;

    /**
     * If we use #GNUNET_CRYPTO_BSA_RSA in @a cipher.
     */
    struct GNUNET_CRYPTO_RsaPrivateKey *rsa_private_key;

  } details;
};


/**
 * @brief Blinded message ready for blind signing.
 */
struct GNUNET_CRYPTO_BlindedMessage
{
  /**
   * Type of the sign blinded message
   */
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Details, depending on @e cipher.
   */
  union
  {
    /**
     * If we use #GNUNET_CRYPTO_BSA_CS in @a cipher.
     */
    struct GNUNET_CRYPTO_CsBlindedMessage cs_blinded_message;

    /**
     * If we use #GNUNET_CRYPTO_BSA_RSA in @a cipher.
     */
    struct GNUNET_CRYPTO_RsaBlindedMessage rsa_blinded_message;

  } details;
};


/**
 * Secret r for Cs denominations
 */
struct GNUNET_CRYPTO_CSPrivateRPairP
{
  struct GNUNET_CRYPTO_CsRSecret r[2];
};


/**
 * @brief Input needed for blinding a message.
 */
struct GNUNET_CRYPTO_BlindingInputValues
{

  /**
   * Type of the signature.
   */
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher;

  /**
   * Reference counter.
   */
  unsigned int rc;

  /**
   * Details, depending on @e cipher.
   */
  union
  {
    /**
     * If we use #GNUNET_CRYPTO_BSA_CS in @a cipher.
     */
    struct GNUNET_CRYPTO_CSPublicRPairP cs_values;

  } details;

};


/**
 * Nonce used to deterministiacally derive input values
 * used in multi-round blind signature protocols.
 */
union GNUNET_CRYPTO_BlindSessionNonce
{
  /**
   * Nonce used when signing with CS.
   */
  struct GNUNET_CRYPTO_CsSessionNonce cs_nonce;
};


/**
 * Compute blinding input values for a given @a nonce and
 * @a salt.
 *
 * @param bsign_priv private key to compute input values for
 * @param nonce session nonce to derive input values from
 * @param salt salt to include in derivation logic
 * @return blinding input values
 */
struct GNUNET_CRYPTO_BlindingInputValues *
GNUNET_CRYPTO_get_blinding_input_values (
  const struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv,
  const union GNUNET_CRYPTO_BlindSessionNonce *nonce,
  const char *salt);


/**
 * Decrement reference counter of a @a bsign_pub, and free it if it reaches zero.
 *
 * @param[in] bsign_pub key to free
 */
void
GNUNET_CRYPTO_blind_sign_pub_decref (
  struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub);


/**
 * Decrement reference counter of a @a bsign_priv, and free it if it reaches zero.
 *
 * @param[in] bsign_priv key to free
 */
void
GNUNET_CRYPTO_blind_sign_priv_decref (
  struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv);


/**
 * Decrement reference counter of a @a ub_sig, and free it if it reaches zero.
 *
 * @param[in] ub_sig signature to free
 */
void
GNUNET_CRYPTO_unblinded_sig_decref (
  struct GNUNET_CRYPTO_UnblindedSignature *ub_sig);


/**
 * Decrement reference counter of a @a blind_sig, and free it if it reaches zero.
 *
 * @param[in] blind_sig signature to free
 */
void
GNUNET_CRYPTO_blinded_sig_decref (
  struct GNUNET_CRYPTO_BlindedSignature *blind_sig);


/**
 * Decrement reference counter of a @a bm, and free it if it reaches zero.
 *
 * @param[in] bm blinded message to free
 */
void
GNUNET_CRYPTO_blinded_message_decref (
  struct GNUNET_CRYPTO_BlindedMessage *bm);


/**
 * Increment reference counter of the given @a bm.
 *
 * @param[in,out] bm blinded message to increment reference counter for
 * @return alias of @a bm with RC incremented
 */
struct GNUNET_CRYPTO_BlindedMessage *
GNUNET_CRYPTO_blinded_message_incref (
  struct GNUNET_CRYPTO_BlindedMessage *bm);


/**
 * Increment reference counter of the given @a bi.
 *
 * @param[in,out] bi blinding input values to increment reference counter for
 * @return alias of @a bi with RC incremented
 */
struct GNUNET_CRYPTO_BlindingInputValues *
GNUNET_CRYPTO_blinding_input_values_incref (
  struct GNUNET_CRYPTO_BlindingInputValues *bm);


/**
 * Decrement reference counter of the given @a bi, and free it if it reaches
 * zero.
 *
 * @param[in,out] bi blinding input values to decrement reference counter for
 */
void
GNUNET_CRYPTO_blinding_input_values_decref (
  struct GNUNET_CRYPTO_BlindingInputValues *bm);


/**
 * Increment reference counter of the given @a bsign_pub.
 *
 * @param[in,out] bsign_pub public key to increment reference counter for
 * @return alias of @a bsign_pub with RC incremented
 */
struct GNUNET_CRYPTO_BlindSignPublicKey *
GNUNET_CRYPTO_bsign_pub_incref (
  struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub);


/**
 * Increment reference counter of the given @a bsign_priv.
 *
 * @param[in,out] bsign_priv private key to increment reference counter for
 * @return alias of @a bsign_priv with RC incremented
 */
struct GNUNET_CRYPTO_BlindSignPrivateKey *
GNUNET_CRYPTO_bsign_priv_incref (
  struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv);


/**
 * Increment reference counter of the given @a ub_sig.
 *
 * @param[in,out] ub_sig signature to increment reference counter for
 * @return alias of @a ub_sig with RC incremented
 */
struct GNUNET_CRYPTO_UnblindedSignature *
GNUNET_CRYPTO_ub_sig_incref (struct GNUNET_CRYPTO_UnblindedSignature *ub_sig);


/**
 * Increment reference counter of the given @a blind_sig.
 *
 * @param[in,out] blind_sig signature to increment reference counter for
 * @return alias of @a blind_sig with RC incremented
 */
struct GNUNET_CRYPTO_BlindedSignature *
GNUNET_CRYPTO_blind_sig_incref (
  struct GNUNET_CRYPTO_BlindedSignature *blind_sig);


/**
 * Compare two denomination public keys.
 *
 * @param bp1 first key
 * @param bp2 second key
 * @return 0 if the keys are equal, otherwise -1 or 1
 */
int
GNUNET_CRYPTO_bsign_pub_cmp (
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bp1,
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bp2);


/**
 * Compare two denomination signatures.
 *
 * @param sig1 first signature
 * @param sig2 second signature
 * @return 0 if the keys are equal, otherwise -1 or 1
 */
int
GNUNET_CRYPTO_ub_sig_cmp (const struct GNUNET_CRYPTO_UnblindedSignature *sig1,
                          const struct GNUNET_CRYPTO_UnblindedSignature *sig2);


/**
 * Compare two blinded denomination signatures.
 *
 * @param sig1 first signature
 * @param sig2 second signature
 * @return 0 if the keys are equal, otherwise -1 or 1
 */
int
GNUNET_CRYPTO_blind_sig_cmp (
  const struct GNUNET_CRYPTO_BlindedSignature *sig1,
  const struct GNUNET_CRYPTO_BlindedSignature *sig2);


/**
 * Compare two blinded messages.
 *
 * @param bp1 first blinded message
 * @param bp2 second blinded message
 * @return 0 if the keys are equal, otherwise -1 or 1
 */
int
GNUNET_CRYPTO_blinded_message_cmp (
  const struct GNUNET_CRYPTO_BlindedMessage *bp1,
  const struct GNUNET_CRYPTO_BlindedMessage *bp2);


/**
 * Initialize public-private key pair for blind signatures.
 *
 * For #GNUNET_CRYPTO_BSA_RSA, an additional "unsigned int"
 * argument with the number of bits for 'n' (e.g. 2048) must
 * be passed.
 *
 * @param[out] bsign_priv where to write the private key with RC 1
 * @param[out] bsign_pub where to write the public key with RC 1
 * @param cipher which type of cipher to use
 * @param ... RSA key size (eg. 2048/3072/4096)
 * @return #GNUNET_OK on success, #GNUNET_NO if parameterst were invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_blind_sign_keys_create (
  struct GNUNET_CRYPTO_BlindSignPrivateKey **bsign_priv,
  struct GNUNET_CRYPTO_BlindSignPublicKey **bsign_pub,
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher,
  ...);


/**
 * Initialize public-private key pair for blind signatures.
 *
 * For #GNUNET_CRYPTO_BSA_RSA, an additional "unsigned int"
 * argument with the number of bits for 'n' (e.g. 2048) must
 * be passed.
 *
 * @param[out] bsign_priv where to write the private key with RC 1
 * @param[out] bsign_pub where to write the public key with RC 1
 * @param cipher which type of cipher to use
 * @param ap RSA key size (eg. 2048/3072/4096)
 * @return #GNUNET_OK on success, #GNUNET_NO if parameterst were invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_blind_sign_keys_create_va (
  struct GNUNET_CRYPTO_BlindSignPrivateKey **bsign_priv,
  struct GNUNET_CRYPTO_BlindSignPublicKey **bsign_pub,
  enum GNUNET_CRYPTO_BlindSignatureAlgorithm cipher,
  va_list ap);


/**
 * @brief Type of blinding secrets.  Must be exactly 32 bytes (DB).
 */
union GNUNET_CRYPTO_BlindingSecretP
{
  /**
   * Clause Schnorr nonce.
   */
  struct GNUNET_CRYPTO_CsBlindingNonce nonce;

  /**
   * Variant for RSA for blind signatures.
   */
  struct GNUNET_CRYPTO_RsaBlindingKeySecret rsa_bks;
};


/**
 * Blind message for blind signing with @a dk using blinding secret @a coin_bks.
 *
 * @param bsign_pub public key to blind for
 * @param bks blinding secret to use
 * @param nonce nonce used to obtain @a alg_values
 *        can be NULL if input values are not used for the cipher
 * @param message message to sign
 * @param message_size number of bytes in @a message
 * @param alg_values algorithm specific values to blind the @a message
 * @return blinded message to give to signer, NULL on error
 */
struct GNUNET_CRYPTO_BlindedMessage *
GNUNET_CRYPTO_message_blind_to_sign (
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub,
  const union GNUNET_CRYPTO_BlindingSecretP *bks,
  const union GNUNET_CRYPTO_BlindSessionNonce *nonce,
  const void *message,
  size_t message_size,
  const struct GNUNET_CRYPTO_BlindingInputValues *alg_values);


/**
 * Create blind signature.
 *
 * @param bsign_priv private key to use for signing
 * @param salt salt value to use for the HKDF,
 *        can be NULL if input values are not used for the cipher
 * @param blinded_message the already blinded message to sign
 * @return blind signature with RC=1, NULL on failure
 */
struct GNUNET_CRYPTO_BlindedSignature *
GNUNET_CRYPTO_blind_sign (
  const struct GNUNET_CRYPTO_BlindSignPrivateKey *bsign_priv,
  const char *salt,
  const struct GNUNET_CRYPTO_BlindedMessage *blinded_message);


/**
 * Unblind blind signature.
 *
 * @param blinded_sig the blind signature
 * @param bks blinding secret to use
 * @param message message that was supposedly signed
 * @param message_size number of bytes in @a message
 * @param alg_values algorithm specific values
 * @param bsign_pub public key used for signing
 * @return unblinded signature with RC=1, NULL on error
 */
struct GNUNET_CRYPTO_UnblindedSignature *
GNUNET_CRYPTO_blind_sig_unblind (
  const struct GNUNET_CRYPTO_BlindedSignature *blinded_sig,
  const union GNUNET_CRYPTO_BlindingSecretP *bks,
  const void *message,
  size_t message_size,
  const struct GNUNET_CRYPTO_BlindingInputValues *alg_values,
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub);


/**
 * Verify signature made blindly.
 *
 * @param bsign_pub public key
 * @param ub_sig signature made blindly with the private key
 * @param message message that was supposedly signed
 * @param message_size number of bytes in @a message
 * @return #GNUNET_OK if the signature is valid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_blind_sig_verify (
  const struct GNUNET_CRYPTO_BlindSignPublicKey *bsign_pub,
  const struct GNUNET_CRYPTO_UnblindedSignature *ub_sig,
  const void *message,
  size_t message_size);


/**
 * Get the compacted length of a #GNUNET_CRYPTO_PublicKey.
 * Compacted means that it returns the minimum number of bytes this
 * key is long, as opposed to the union structure inside
 * #GNUNET_CRYPTO_PublicKey.
 * Useful for compact serializations.
 *
 * @param key the key.
 * @return -1 on error, else the compacted length of the key.
 */
ssize_t
GNUNET_CRYPTO_public_key_get_length (const struct
                                     GNUNET_CRYPTO_PublicKey *key);

/**
 * Reads a #GNUNET_CRYPTO_PublicKey from a compact buffer.
 * The buffer has to contain at least the compacted length of
 * a #GNUNET_CRYPTO_PublicKey in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the buffer does not contain a valid key, it returns -2 as error.
 *
 * @param buffer the buffer
 * @param len the length of buffer
 * @param key the key
 * @param the amount of bytes read from the buffer
 * @return #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_read_public_key_from_buffer (
  const void *buffer,
  size_t len,
  struct GNUNET_CRYPTO_PublicKey *key,
  size_t *read);

/**
 * Get the compacted length of a #GNUNET_CRYPTO_PrivateKey.
 * Compacted means that it returns the minimum number of bytes this
 * key is long, as opposed to the union structure inside
 * #GNUNET_CRYPTO_PrivateKey.
 * Useful for compact serializations.
 *
 * @param key the key.
 * @return -1 on error, else the compacted length of the key.
 */
ssize_t
GNUNET_CRYPTO_private_key_get_length (
  const struct GNUNET_CRYPTO_PrivateKey *key);


/**
 * Writes a #GNUNET_CRYPTO_PublicKey to a compact buffer.
 * The buffer requires space for at least the compacted length of
 * a #GNUNET_CRYPTO_PublicKey in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the key is not valid, it returns -2 as error.
 *
 * @param key the key
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes written to the buffer
 */
ssize_t
GNUNET_CRYPTO_write_public_key_to_buffer (const struct
                                          GNUNET_CRYPTO_PublicKey *key,
                                          void*buffer,
                                          size_t len);


/**
 * Reads a #GNUNET_CRYPTO_PrivateKey from a compact buffer.
 * The buffer has to contain at least the compacted length of
 * a #GNUNET_CRYPTO_PrivateKey in bytes.
 * If the buffer is too small, the function returns GNUNET_SYSERR as error.
 *
 * @param buffer the buffer
 * @param len the length of buffer
 * @param key the key
 * @param the amount of bytes read from the buffer
 * @return #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_read_private_key_from_buffer (
  const void*buffer,
  size_t len,
  struct GNUNET_CRYPTO_PrivateKey *key,
  size_t *read);


/**
 * Writes a #GNUNET_CRYPTO_PrivateKey to a compact buffer.
 * The buffer requires space for at least the compacted length of
 * a #GNUNET_CRYPTO_PrivateKey in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the key is not valid, it returns -2 as error.
 *
 * @param key the key
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes written to the buffer
 */
ssize_t
GNUNET_CRYPTO_write_private_key_to_buffer (
  const struct GNUNET_CRYPTO_PrivateKey *key,
  void*buffer,
  size_t len);


/**
 * Get the compacted length of a #GNUNET_CRYPTO_Signature.
 * Compacted means that it returns the minimum number of bytes this
 * signature is long, as opposed to the union structure inside
 * #GNUNET_CRYPTO_Signature.
 * Useful for compact serializations.
 *
 * @param sig the signature.
 * @return -1 on error, else the compacted length of the signature.
 */
ssize_t
GNUNET_CRYPTO_signature_get_length (
  const struct GNUNET_CRYPTO_Signature *sig);


/**
 * Get the compacted length of a signature by type.
 * Compacted means that it returns the minimum number of bytes this
 * signature is long, as opposed to the union structure inside
 * #GNUNET_CRYPTO_Signature.
 * Useful for compact serializations.
 *
 * @param sig the signature.
 * @return -1 on error, else the compacted length of the signature.
 */
ssize_t
GNUNET_CRYPTO_signature_get_raw_length_by_type (uint32_t type);


/**
 * Reads a #GNUNET_CRYPTO_Signature from a compact buffer.
 * The buffer has to contain at least the compacted length of
 * a #GNUNET_CRYPTO_Signature in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the buffer does not contain a valid key, it returns -2 as error.
 *
 * @param sig the signature
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes read from the buffer
 */
ssize_t
GNUNET_CRYPTO_read_signature_from_buffer (
  struct GNUNET_CRYPTO_Signature *sig,
  const void*buffer,
  size_t len);


/**
 * Writes a #GNUNET_CRYPTO_Signature to a compact buffer.
 * The buffer requires space for at least the compacted length of
 * a #GNUNET_CRYPTO_Signature in bytes.
 * If the buffer is too small, the function returns -1 as error.
 * If the key is not valid, it returns -2 as error.
 *
 * @param sig the signature
 * @param buffer the buffer
 * @param len the length of buffer
 * @return -1 or -2 on error, else the amount of bytes written to the buffer
 */
ssize_t
GNUNET_CRYPTO_write_signature_to_buffer (
  const struct GNUNET_CRYPTO_Signature *sig,
  void*buffer,
  size_t len);


/**
 * @brief Sign a given block.
 *
 * The @a purpose data is the beginning of the data of which the signature is
 * to be created. The `size` field in @a purpose must correctly indicate the
 * number of bytes of the data structure, including its header. If possible,
 * use #GNUNET_CRYPTO_sign() instead of this function.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param[out] sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_sign_ (
  const struct GNUNET_CRYPTO_PrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_Signature *sig);

/**
 * @brief Sign a given block.
 *
 * The @a purpose data is the beginning of the data of which the signature is
 * to be created. The `size` field in @a purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 * The signature payload and length depends on the key type.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param[out] sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_sign_raw_ (
  const struct GNUNET_CRYPTO_PrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  unsigned char *sig);


/**
 * @brief Sign a given block with #GNUNET_CRYPTO_PrivateKey.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param priv private key to use for the signing
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param[out] sig where to write the signature
 */
#define GNUNET_CRYPTO_sign(priv,ps,sig) do {                \
    /* check size is set correctly */                                     \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));         \
    /* check 'ps' begins with the purpose */                              \
    GNUNET_static_assert (((void*) (ps)) ==                               \
                          ((void*) &(ps)->purpose));                      \
    GNUNET_assert (GNUNET_OK ==                                           \
                   GNUNET_CRYPTO_sign_ (priv,               \
                                        &(ps)->purpose,             \
                                        sig));                      \
} while (0)


/**
 * @brief Verify a given signature.
 *
 * The @a validate data is the beginning of the data of which the signature
 * is to be verified. The `size` field in @a validate must correctly indicate
 * the number of bytes of the data structure, including its header.  If @a
 * purpose does not match the purpose given in @a validate (the latter must be
 * in big endian), signature verification fails.  If possible,
 * use #GNUNET_CRYPTO_signature_verify() instead of this function (only if @a validate
 * is not fixed-size, you must use this function directly).
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_signature_verify_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const struct GNUNET_CRYPTO_Signature *sig,
  const struct GNUNET_CRYPTO_PublicKey *pub);

/**
 * @brief Verify a given signature.
 *
 * The @a validate data is the beginning of the data of which the signature
 * is to be verified. The `size` field in @a validate must correctly indicate
 * the number of bytes of the data structure, including its header.  If @a
 * purpose does not match the purpose given in @a validate (the latter must be
 * in big endian), signature verification fails.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_signature_verify_raw_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const unsigned char *sig,
  const struct GNUNET_CRYPTO_PublicKey *pub);


/**
 * @brief Verify a given signature with #GNUNET_CRYPTO_PublicKey.
 *
 * The @a ps data must be a fixed-size struct for which the signature is to be
 * created. The `size` field in @a ps->purpose must correctly indicate the
 * number of bytes of the data structure, including its header.
 *
 * @param purp purpose of the signature, must match 'ps->purpose.purpose'
 *              (except in host byte order)
 * @param ps packed struct with what to sign, MUST begin with a purpose
 * @param sig where to read the signature from
 * @param pub public key to use for the verifying
 */
#define GNUNET_CRYPTO_signature_verify(purp,ps,sig,pub) ({             \
    /* check size is set correctly */                                     \
    GNUNET_assert (ntohl ((ps)->purpose.size) == sizeof (*(ps)));         \
    /* check 'ps' begins with the purpose */                              \
    GNUNET_static_assert (((void*) (ps)) ==                               \
                          ((void*) &(ps)->purpose));                      \
    GNUNET_CRYPTO_signature_verify_ (purp,                              \
                                     &(ps)->purpose,                    \
                                     sig,                               \
                                     pub);                              \
  })


/**
 * Creates a (Base32) string representation of the public key.
 * The resulting string encodes a compacted representation of the key.
 * See also #GNUNET_CRYPTO_key_get_length.
 *
 * @param key the key.
 * @return the string representation of the key, or NULL on error.
 */
char *
GNUNET_CRYPTO_public_key_to_string (
  const struct GNUNET_CRYPTO_PublicKey *key);


/**
 * Creates a (Base32) string representation of the private key.
 * The resulting string encodes a compacted representation of the key.
 * See also #GNUNET_CRYPTO_key_get_length.
 *
 * @param key the key.
 * @return the string representation of the key, or NULL on error.
 */
char *
GNUNET_CRYPTO_private_key_to_string (
  const struct GNUNET_CRYPTO_PrivateKey *key);


/**
 * Parses a (Base32) string representation of the public key.
 * See also #GNUNET_CRYPTO_public_key_to_string.
 *
 * @param str the encoded key.
 * @param key where to write the key.
 * @return GNUNET_SYSERR on error.
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_public_key_from_string (const char*str,
                                      struct GNUNET_CRYPTO_PublicKey *key);


/**
 * Parses a (Base32) string representation of the private key.
 * See also #GNUNET_CRYPTO_private_key_to_string.
 *
 * @param str the encoded key.
 * @param key where to write the key.
 * @return GNUNET_SYSERR on error.
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_private_key_from_string (const char*str,
                                       struct GNUNET_CRYPTO_PrivateKey *key);


/**
 * Retrieves the public key representation of a private key.
 *
 * @param privkey the private key.
 * @param key the public key result.
 * @return GNUNET_SYSERR on error.
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_key_get_public (const struct
                              GNUNET_CRYPTO_PrivateKey *privkey,
                              struct GNUNET_CRYPTO_PublicKey *key);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CRYPTO_LIB_H */
#endif

/** @} */ /* end of group addition */

/* end of gnunet_crypto_lib.h */
