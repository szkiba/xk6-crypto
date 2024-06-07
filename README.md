# xk6-crypto

> [!WARNING]
> This extension is deprecated. In the meantime, [k6 supports webcrypto](https://grafana.com/docs/k6/latest/javascript-api/k6-experimental/webcrypto/), it is advisable to use it in new tests.
> If you need this extension because of your old tests or if you want to continue development, feel free to fork it.


A k6 extension for using extended crypto functions, mostly from [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto).

Built for [k6](https://go.k6.io/k6) using [xk6](https://github.com/grafana/xk6).

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
  $ go install go.k6.io/xk6/cmd/xk6@latest
  ```

2. Build the binary:
  ```bash
  $ xk6 build --with github.com/szkiba/xk6-crypto@latest
  ```
