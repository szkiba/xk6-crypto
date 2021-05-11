/**
 * Collection of crypto functions, mostly from [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto).
 *
 * ## Usage
 *
 * Import an entire module's contents:
 * ```JavaScript
 * import * as xcrypto from "k6/x/crypto";
 * ```
 *
 * Import a single export from a module:
 * ```JavaScript
 * import { hkdf } from "k6/x/crypto";
 * ```
 */

/**
 * Array of numbers. The number range is from 0 to 255.
 */
export type bytes = number[];

/**
 * Byte array convertible types
 */
export type ByteArrayLike = ArrayBuffer | string | bytes;

/**
 * HKDF is a simple key derivation function defined in RFC 5869.
 *
 * The given `secret`, `salt` and `info` are used with the `hash` to derive a key of `keylen` bytes.
 *
 * An error will be thrown if any of the input aguments specify invalid values or types.
 *
 * Supported hash function names:
 *  - md5
 *  - sha1
 *  - sha256
 *  - sha384
 *  - sha512
 *
 * @param hash The hash algorithm to use.
 * @param secret The secret key. It must be at least one byte in length.
 * @param salt The salt value, can be zero-length or null.
 * @param info Additional info value, can be zero-length or null and cannot be more than 1024 bytes.
 * @param keylen The length of the key to generate. Must be greater than 0. The maximum allowable value is 255 times the number of bytes produced by the selected hash function.
 * @returns The generated derived key.
 */

export declare function hkdf(
  hash: string,
  secret: ByteArrayLike,
  salt: ByteArrayLike,
  info: ByteArrayLike,
  keylen: number
): ArrayBuffer;

/**
 * Password-Based Key Derivation Function 2 (PBKDF2) implementation.
 *
 * A selected HMAC digest algorithm specified by `hash` is applied to derive a key of the requested
 * byte length (`keylen`) from the `password`, `salt` and iterations (`iter`).
 * The key is derived based on the method described as PBKDF2 with the HMAC variant using the supplied hash function.
 * Supported hash function names:
 *  - md5
 *  - sha1
 *  - sha256
 *  - sha384
 *  - sha512
 *
 * @param password The source password for key generation.
 * @param salt The salt value, can be zero-length or null.
 * @param iter The number of iterations.
 * @param keylen The length of the key to generate.
 * @param hash The hash algorithm to use.
 * @returns The generated derived key.
 */
export declare function pbkdf2(
  password: ByteArrayLike,
  salt: ByteArrayLike,
  iter: number,
  keylen: number,
  hash: string
): ArrayBuffer;

/**
 * Asymmetric key pair.
 */
interface KeyPair {
  /** The public key part of the key pair. */
  publicKey: ArrayBuffer;
  /** The private key part of the key pair. */
  privateKey: ArrayBuffer;
}

/**
 * Generates a new asymmetric key pair of the given algorithm (`algorithm`) or import exising private key from `seed`.
 *
 * @param algorithm Key algorithm, supported values: `ed25519`
 * @param seed Seed value when importing private key
 * @returns The generated key pair (an object with `publicKey` and `privateKey` properties)
 */
export declare function generateKeyPair(algorithm: string, seed?: ByteArrayLike): KeyPair;

/**
 * Elliptic-curve Diffie–Hellman (ECDH) implementation.
 *
 * ECDH is a key agreement protocol that allows two parties, each having an elliptic-curve
 * public–private key pair, to establish a shared secret over an insecure channel.
 * This shared secret may be directly used as a key, or to derive another key.
 * The key, or the derived key, can then be used to encrypt subsequent communications using a symmetric-key cipher.
 *
 * @param algorithm Key algorithm, supported values: `ed25519`
 * @param privateKey Alice's private key
 * @param publicKey Bob's public key
 * @returns The derived shared secret. The result will be same with Bob's private key and Alice's public key.
 */
export declare function ecdh(algorithm: string, privateKey: ArrayBuffer, publicKey: ArrayBuffer): ArrayBuffer;
