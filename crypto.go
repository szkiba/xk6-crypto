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
	"strings"

	"github.com/dop251/goja"
	ed25519X "github.com/oasisprotocol/ed25519"
	x25519X "github.com/oasisprotocol/ed25519/extra/x25519"
	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Register the extensions on module initialization.
func init() {
	modules.Register("k6/x/crypto", New())
}

type KeyPair struct {
	PrivateKey goja.ArrayBuffer `js:"privateKey"`
	PublicKey  goja.ArrayBuffer `js:"publicKey"`
}

type (
	Crypto struct{}

	ModuleInstance struct {
		vu modules.VU
		*Crypto
	}
)

var _ modules.Instance = &ModuleInstance{}

func New() *Crypto {
	return &Crypto{}
}

// NewModuleInstance implements the modules.Module interface and returns
// a new instance for each VU.
func (*Crypto) NewModuleInstance(vu modules.VU) modules.Instance {
	return &ModuleInstance{
		vu:     vu,
		Crypto: &Crypto{},
	}
}

// Exports implements the modules.Instance interface and returns
// the exports of the JS module.
func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{
		Default: &Crypto{},
		Named: map[string]interface{}{
			"hkdf":            mi.Crypto.Hkdf,
			"pbkdf2":          mi.Crypto.Pbkdf2,
			"generateKeyPair": mi.Crypto.GenerateKeyPair,
			"ecdh":            mi.Crypto.Ecdh,
		}}
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

func bytes(in goja.Value) ([]byte, error) {
	if in == nil || in.Export() == nil {
		return nil, nil
	}

	val, err := common.ToBytes(in.Export())
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return val, nil
}

//Hkdf hash string, secretIn, saltIn, infoIn interface{}, keylen int
func (c *Crypto) Hkdf(call goja.FunctionCall, rt *goja.Runtime) goja.Value {
	hashIn := call.Argument(0).String()
	alg, ok := hashes[strings.ToLower(hashIn)]
	if !ok {
		return rt.ToValue(fmt.Sprintf("%s: %s", ErrUnsupportedHash.Error(), hashIn))
	}
	keylen := int(call.Argument(4).ToInteger())
	if keylen <= 0 || keylen > alg.size*hkdfMaxFactor {
		return rt.ToValue(fmt.Sprintf("%s: %d, allowed range 1..%d", ErrInvalidKeyLen.Error(), keylen, alg.size*hkdfMaxFactor))
	}

	var secret, salt, info []byte
	var err error
	if secret, err = bytes(call.Argument(1)); err != nil {
		return rt.ToValue(fmt.Sprintf("error: secret %v", err))
	}
	if salt, err = bytes(call.Argument(2)); err != nil {
		return rt.ToValue(fmt.Sprintf("error: salt %v", err))
	}
	if info, err = bytes(call.Argument(3)); err != nil {
		return rt.ToValue(fmt.Sprintf("error: info %v", err))
	}

	r := hkdf.New(alg.fn, secret, salt, info)

	b := make([]byte, keylen)

	if _, err = r.Read(b); err != nil {
		return rt.ToValue(err.Error())
	}

	return rt.ToValue(rt.NewArrayBuffer(b))
}

//Pbkdf2 passwordIn, saltIn interface{}, iter, keylen int, hash string
func (c *Crypto) Pbkdf2(call goja.FunctionCall, rt *goja.Runtime /*passwordIn, saltIn interface{}, iter, keylen int, hash string*/) goja.Value {
	hashIn := call.Argument(4).String()
	alg, ok := hashes[strings.ToLower(hashIn)]
	if !ok {
		return rt.ToValue(fmt.Sprintf("%s: %s", ErrUnsupportedHash.Error(), hashIn))
	}
	keylen := int(call.Argument(3).ToInteger())
	if keylen <= 0 {
		return rt.ToValue(fmt.Sprintf("%s: %d, allowed range 1..∞", ErrInvalidKeyLen.Error(), keylen))
	}
	iter := int(call.Argument(2).ToInteger())

	var password, salt []byte
	var err error
	if password, err = bytes(call.Argument(0)); err != nil {
		return rt.ToValue(fmt.Sprintf("error: secret %v", err))
	}
	if salt, err = bytes(call.Argument(1)); err != nil {
		return rt.ToValue(fmt.Sprintf("error: salt %v", err))
	}

	b := pbkdf2.Key(password, salt, iter, keylen, alg.fn)

	return rt.ToValue(rt.NewArrayBuffer(b))
}

//GenerateKeyPair algorithm string, seedIn []byte
func (c *Crypto) GenerateKeyPair(call goja.FunctionCall, rt *goja.Runtime /*algorithm string, seedIn interface{}*/) goja.Value {
	algorithm := call.Argument(0).String()
	alg := strings.ToLower(algorithm)

	seed, err := bytes(call.Argument(1))
	if err != nil {
		return rt.ToValue(fmt.Sprintf("error: bad seed: %v", err))
	}

	if alg == "ed25519" {
		if seed != nil {
			priv := ed25519.NewKeyFromSeed(seed)
			pub, ok := priv.Public().(ed25519.PublicKey)

			if !ok {
				return rt.ToValue(fmt.Sprintf("%v", ErrUnsupportedAlgorithm))
			}

			return rt.ToValue(&KeyPair{PublicKey: rt.NewArrayBuffer(pub), PrivateKey: rt.NewArrayBuffer(priv)})
		}

		if pub, priv, gerr := ed25519.GenerateKey(rand.Reader); gerr != nil {
			return rt.ToValue(fmt.Sprintf("error: %v", gerr))
		} else {
			return rt.ToValue(&KeyPair{PublicKey: rt.NewArrayBuffer(pub), PrivateKey: rt.NewArrayBuffer(priv)})
		}
	}

	return rt.ToValue(fmt.Sprintf("%v: %s", ErrUnsupportedAlgorithm, algorithm))
}

func (c *Crypto) Ecdh(call goja.FunctionCall, rt *goja.Runtime /*algorithm string, privateKey, publicKey goja.ArrayBuffer*/) goja.Value {
	algorithm := call.Argument(0).String()
	alg := strings.ToLower(algorithm)

	var privateKey, publicKey []byte
	var err error
	if privateKey, err = bytes(call.Argument(1)); err != nil {
		return rt.ToValue(fmt.Sprintf("error: bad privateKey: %v", err))
	}

	if publicKey, err = bytes(call.Argument(2)); err != nil {
		return rt.ToValue(fmt.Sprintf("error: bad publicKey: %v", err))
	}

	if alg == "ed25519" {
		priv := ed25519.PrivateKey(privateKey)
		pub := ed25519.PublicKey(publicKey)

		var b []byte
		b, err = sharedSecretED(priv, pub)
		if err != nil {
			return rt.ToValue(fmt.Sprintf("error: unable to generate secret: %v", err))
		}

		return rt.ToValue(rt.NewArrayBuffer(b))
	}

	return rt.ToValue(fmt.Sprintf("%v: %s", ErrUnsupportedAlgorithm, algorithm))
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
