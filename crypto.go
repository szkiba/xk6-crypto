// MIT License
//
// Copyright (c) 2021 Iván Szkiba
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package crypto

import ( // nolint:gci

	"crypto/ed25519"
	"crypto/md5" // nolint
	"crypto/rand"
	"crypto/sha1" // nolint
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strings"

	"github.com/dop251/goja"
	ed25519X "github.com/oasisprotocol/ed25519"
	x25519X "github.com/oasisprotocol/ed25519/extra/x25519"
	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type KeyPair struct {
	PrivateKey interface{} `js:"privateKey"`
	PublicKey  interface{} `js:"publicKey"`
}

type Crypto struct {
	vu modules.VU
}

func newCrypto(vu modules.VU) *Crypto {
	return &Crypto{
		vu: vu,
	}
}

type hashInfo struct {
	fn   func() hash.Hash
	size int
}

var (
	ErrUnsupportedHash      = errors.New("unsupported hash")
	ErrInvalidKeyLen        = errors.New("invalid keylen")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

	hashes = map[string]hashInfo{
		"md5":    {fn: md5.New, size: md5.Size},
		"sha1":   {fn: sha1.New, size: sha1.Size},
		"sha256": {fn: sha256.New, size: sha256.Size},
		"sha384": {fn: sha512.New384, size: sha512.Size384},
		"sha512": {fn: sha512.New, size: sha512.Size},
	}
)

const hkdfMaxFactor = 255

func bytes(in interface{}) ([]byte, error) {
	if in == nil || reflect.ValueOf(in).IsZero() {
		return nil, nil
	}

	val, err := common.ToBytes(in)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return val, nil
}

func (c *Crypto) Hkdf(hash string, secretIn, saltIn, infoIn interface{}, keylen int) (interface{}, error) {
	alg, ok := hashes[strings.ToLower(hash)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedHash, hash)
	}

	if keylen <= 0 || keylen > alg.size*hkdfMaxFactor {
		return nil, fmt.Errorf("%w: %d, allowed range 1..%d", ErrInvalidKeyLen, keylen, alg.size*hkdfMaxFactor)
	}

	secret, err := bytes(secretIn)
	if err != nil {
		return nil, err
	}

	salt, err := bytes(saltIn)
	if err != nil {
		return nil, err
	}

	info, err := bytes(infoIn)
	if err != nil {
		return nil, err
	}

	r := hkdf.New(alg.fn, secret, salt, info)

	b := make([]byte, keylen)

	if _, err := r.Read(b); err != nil {
		return nil, err
	}

	return c.vu.Runtime().NewArrayBuffer(b), nil
}

func (c *Crypto) Pbkdf2(passwordIn, saltIn interface{}, iter, keylen int, hash string) (interface{}, error) {
	alg, ok := hashes[strings.ToLower(hash)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedHash, hash)
	}

	if keylen <= 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidKeyLen, keylen)
	}

	password, err := bytes(passwordIn)
	if err != nil {
		return nil, err
	}

	salt, err := bytes(saltIn)
	if err != nil {
		return nil, err
	}

	b := pbkdf2.Key(password, salt, iter, keylen, alg.fn)

	return c.vu.Runtime().NewArrayBuffer(b), nil
}

func (c *Crypto) GenerateKeyPair(algorithm string, seedIn interface{}) (*KeyPair, error) {
	alg := strings.ToLower(algorithm)
	rt := c.vu.Runtime()

	seed, err := bytes(seedIn)
	if err != nil {
		return nil, err
	}

	if alg == "ed25519" {
		if seed != nil {
			priv := ed25519.NewKeyFromSeed(seed)
			pub, ok := priv.Public().(ed25519.PublicKey)

			if !ok {
				return nil, ErrUnsupportedAlgorithm
			}

			return &KeyPair{PublicKey: rt.NewArrayBuffer(pub), PrivateKey: rt.NewArrayBuffer(priv)}, nil
		}

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		return &KeyPair{PublicKey: rt.NewArrayBuffer(pub), PrivateKey: rt.NewArrayBuffer(priv)}, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
}

func (c *Crypto) Ecdh(algorithm string, privateKey, publicKey goja.ArrayBuffer) (interface{}, error) {
	alg := strings.ToLower(algorithm)
	rt := c.vu.Runtime()

	if alg == "ed25519" {
		priv := ed25519.PrivateKey(privateKey.Bytes())
		pub := ed25519.PublicKey(publicKey.Bytes())

		b, err := sharedSecretED(priv, pub)
		if err != nil {
			return nil, err
		}

		return rt.NewArrayBuffer(b), nil
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
}

func sharedSecretED(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) ([]byte, error) {
	epriv := ed25519X.NewKeyFromSeed(privateKey.Seed())
	epub := ed25519X.PublicKey(publicKey)

	xpriv := x25519X.EdPrivateKeyToX25519(epriv)
	xpub, _ := x25519X.EdPublicKeyToX25519(epub)

	b, err := x25519X.X25519(xpriv, xpub)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return b, nil
}
