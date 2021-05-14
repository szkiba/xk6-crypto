# xk6-crypto

A k6 extension for using extended crypto functions, mostly from [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto).

Built for [k6](https://go.k6.io/k6) using [xk6](https://github.com/k6io/xk6).

## Usage

Import an entire module's contents:
```JavaScript
import * as xcrypto from "k6/x/crypto";
```

Import a single export from a module:
```JavaScript
import { hkdf } from "k6/x/crypto";
```

## API

Functions:

- [ecdh](docs/README.md#ecdh)
- [generateKeyPair](docs/README.md#generatekeypair)
- [hkdf](docs/README.md#hkdf)
- [pbkdf2](docs/README.md#pbkdf2)

For complete API documentation click [here](docs/README.md)!

## Build

To build a `k6` binary with this extension, first ensure you have the prerequisites:

- [Go toolchain](https://go101.org/article/go-toolchain.html)
- Git

Then:

1. Install `xk6`:
  ```bash
  $ go install github.com/k6io/xk6/cmd/xk6@latest
  ```

2. Build the binary:
  ```bash
  $ xk6 build --with github.com/szkiba/xk6-crypto@latest
  ```
