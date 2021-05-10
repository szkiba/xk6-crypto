# xk6-crypto

Collection of crypto functions, mostly from [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto).

## Usage

Import an entire module's contents:
```JavaScript
import * as xcrypto from "k6/x/crypto";
```

Import a single export from a module:
```JavaScript
import { hkdf } from "k6/x/crypto";
```

## Table of contents

### Interfaces

- [KeyPair](interfaces/keypair.md)

### Type aliases

- [ByteArrayLike](README.md#bytearraylike)
- [bytes](README.md#bytes)

### Functions

- [ecdh](README.md#ecdh)
- [generateKeyPair](README.md#generatekeypair)
- [hkdf](README.md#hkdf)
- [pbkdf2](README.md#pbkdf2)

## Type aliases

### ByteArrayLike

Ƭ **ByteArrayLike**: ArrayBuffer \| *string* \| [*bytes*](README.md#bytes)

Byte array convertible types

___

### bytes

Ƭ **bytes**: *number*[]

Array of numbers. The number range is from 0 to 255.

## Functions

### ecdh

▸ **ecdh**(`keytype`: *string*, `privateKey`: ArrayBuffer, `publicKey`: ArrayBuffer): ArrayBuffer

Elliptic-curve Diffie–Hellman (ECDH) implementation.

ECDH is a key agreement protocol that allows two parties, each having an elliptic-curve
public–private key pair, to establish a shared secret over an insecure channel.
This shared secret may be directly used as a key, or to derive another key.
The key, or the derived key, can then be used to encrypt subsequent communications using a symmetric-key cipher.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `keytype` | *string* | Key type, supported values: `ed25519` |
| `privateKey` | ArrayBuffer | Alice's private key |
| `publicKey` | ArrayBuffer | Bob's public key |

**Returns:** ArrayBuffer

The derived shared secret. The result will be same with Bob's private key and Alice's public key.

___

### generateKeyPair

▸ **generateKeyPair**(`keytype`: *string*, `seed?`: [*ByteArrayLike*](README.md#bytearraylike)): [*KeyPair*](interfaces/keypair.md)

Generates a new asymmetric key pair of the given type (`keytype`) or import exising private key from `seed`.

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `keytype` | *string* | Key pair type, supported values: `ed25519` |
| `seed?` | [*ByteArrayLike*](README.md#bytearraylike) | Seed value when importing private key |

**Returns:** [*KeyPair*](interfaces/keypair.md)

The generated key pair (an object with `publicKey` and `privateKey` properties)

___

### hkdf

▸ **hkdf**(`hash`: *string*, `secret`: [*ByteArrayLike*](README.md#bytearraylike), `salt`: [*ByteArrayLike*](README.md#bytearraylike), `info`: [*ByteArrayLike*](README.md#bytearraylike), `keylen`: *number*): ArrayBuffer

HKDF is a simple key derivation function defined in RFC 5869.

The given `secret`, `salt` and `info` are used with the `hash` to derive a key of `keylen` bytes.

An error will be thrown if any of the input aguments specify invalid values or types.

Supported hash function names:
 - md5
 - sha1
 - sha256
 - sha384
 - sha512

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `hash` | *string* | The hash algorithm to use. |
| `secret` | [*ByteArrayLike*](README.md#bytearraylike) | The secret key. It must be at least one byte in length. |
| `salt` | [*ByteArrayLike*](README.md#bytearraylike) | The salt value, can be zero-length or null. |
| `info` | [*ByteArrayLike*](README.md#bytearraylike) | Additional info value, can be zero-length or null and cannot be more than 1024 bytes. |
| `keylen` | *number* | The length of the key to generate. Must be greater than 0. The maximum allowable value is 255 times the number of bytes produced by the selected hash function. |

**Returns:** ArrayBuffer

The generated derived key.

___

### pbkdf2

▸ **pbkdf2**(`password`: [*ByteArrayLike*](README.md#bytearraylike), `salt`: [*ByteArrayLike*](README.md#bytearraylike), `iter`: *number*, `keylen`: *number*, `hash`: *string*): ArrayBuffer

Password-Based Key Derivation Function 2 (PBKDF2) implementation.

A selected HMAC digest algorithm specified by `hash` is applied to derive a key of the requested
byte length (`keylen`) from the `password`, `salt` and iterations (`iter`).
The key is derived based on the method described as PBKDF2 with the HMAC variant using the supplied hash function.
Supported hash function names:
 - md5
 - sha1
 - sha256
 - sha384
 - sha512

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `password` | [*ByteArrayLike*](README.md#bytearraylike) | The source password for key generation. |
| `salt` | [*ByteArrayLike*](README.md#bytearraylike) | The salt value, can be zero-length or null. |
| `iter` | *number* | The number of iterations. |
| `keylen` | *number* | The length of the key to generate. |
| `hash` | *string* | The hash algorithm to use. |

**Returns:** ArrayBuffer

The generated derived key.
