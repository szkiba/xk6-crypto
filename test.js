/**
 * MIT License
 *
 * Copyright (c) 2021 Iván Szkiba
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { check, group } from "k6";
import { Rate } from "k6/metrics";

import { hkdf, pbkdf2, generateKeyPair, ecdh } from "k6/x/crypto";

export let errors = new Rate("errors");
export let options = { thresholds: { errors: ["rate==0"] } };

function test_hkdf() {
  let key = hkdf("sha256", "top secret", null, null, 64);
  return check(new Uint8Array(key), {
    "Key length": (k) => k.length == 64,
  });
}

function test_pbkdf2() {
  let key = pbkdf2("top secret", null, 10000, 48, "sha256");
  return check(new Uint8Array(key), {
    "Key length": (k) => k.length == 48,
  });
}

function test_generateKeyPair() {
  let pair = generateKeyPair("ed25519");
  return check(pair, {
    "Public Key length": (p) => new Uint8Array(p.publicKey).length == 32,
    "Private Key length": (p) => new Uint8Array(p.privateKey).length == 64,
  });
}

function test_generateKeyPairWithSeed() {
  let pair = generateKeyPair("ed25519", pbkdf2("top secret", null, 10000, 32, "sha256"));

  return check(pair, {
    "Public Key length": (p) => new Uint8Array(p.publicKey).length == 32,
    "Private Key length": (p) => new Uint8Array(p.privateKey).length == 64,
  });
}

function test_ecdh() {
  const alice = generateKeyPair("ed25519");
  const bob = generateKeyPair("ed25519");

  const aliceShared = new Uint8Array(ecdh("ed25519", alice.privateKey, bob.publicKey));
  const bobShared = new Uint8Array(ecdh("ed25519", bob.privateKey, alice.publicKey));

  return check(null, {
    "Shared secrets equals": (p) => aliceShared.every((val, i) => val == bobShared[i]),
  });
}

export default function () {
  for (const key of Object.keys(global)) {
    if (typeof global[key] == "function" && key.startsWith("test")) {
      group(key, () => {
        try {
          errors.add(!global[key]());
        } catch (e) {
          errors.add(!check(e, { [e]: (e) => false }));
        }
      });
    }
  }
}
