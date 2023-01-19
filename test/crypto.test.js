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

export { options } from "./expect.js";
import { describe } from "./expect.js";
import * as xcrypto from 'k6/x/crypto';
import { hkdf, pbkdf2, generateKeyPair, ecdh } from "k6/x/crypto";

export default function () {
  testDefault();
  testModule();
}

export function testModule() {
  describe("hkdf", (t) => {
    const key = hkdf("sha256", "top secret", null, null, 64);
    t.expect(typeof (key) === 'object').as("key type").toBeTruthy();
    t.expect(key.byteLength).as("key length").toEqual(64);
  });

  describe("hkdf: bad hashing algorithm", (t) => {
    const key = hkdf("sha999", "top secret", null, null, 64);
    t.expect(typeof (key) === "string").as("key error").toBeTruthy();
    t.expect(key).as("key error").toEqual('unsupported hash: sha999');
  });

  describe("hkdf: bad bad keylen", (t) => {
    const key = hkdf("sha256", null, null, null, 8161);
    t.expect(typeof (key) === "string").as("key error").toBeTruthy();
    t.expect(key).as("key error").toEqual('invalid keylen: 8161, allowed range 1..8160');
  });

  describe("pbkdf2", (t) => {
    const key = pbkdf2("top secret", null, 10000, 48, "sha256");
    t.expect(key.byteLength).as("key length").toEqual(48);
  });

  describe("pbkdf2: bad hashing algorithm", (t) => {
    const key = pbkdf2("top secret", null, 10000, 48, "sha999");
    t.expect(typeof (key) === 'string').as("key type").toBeTruthy();
    t.expect(key).as("key error").toEqual('unsupported hash: sha999');
  });

  describe("pbkdf2: bad keylen", (t) => {
    const key = pbkdf2("top secret", null, 10000, -1, "sha256");
    t.expect(typeof (key) === 'string').as("key type").toBeTruthy();
    t.expect(key).as("key error").toEqual('invalid keylen: -1, allowed range 1..∞');
  });

  describe("generateKeyPair", (t) => {
    const pair = generateKeyPair("ed25519");
    t.expect(pair.publicKey.byteLength).as("public key length").toEqual(32);
    t.expect(pair.privateKey.byteLength).as("private key length").toEqual(64);
  });

  describe("generateKeyPair with seed", (t) => {
    const pair = generateKeyPair("ed25519", pbkdf2("top secret", null, 10000, 32, "sha256"));
    t.expect(!!pair.publicKey).as("public key exists").toBeTruthy();
    t.expect(!!pair.privateKey).as("private key exists").toBeTruthy();
    t.expect(pair.publicKey.byteLength).as("public key length").toEqual(32);
    t.expect(pair.privateKey.byteLength).as("private key length").toEqual(64);
  });

  describe("ecdh", (t) => {
    const alice = generateKeyPair("ed25519");
    const bob = generateKeyPair("ed25519");

    t.expect(!!alice.publicKey).as("alice public key exists").toBeTruthy();
    t.expect(!!alice.privateKey).as("alice private key exists").toBeTruthy();
    t.expect(!!bob.publicKey).as("bob public key exists").toBeTruthy();
    t.expect(!!bob.privateKey).as("bob private key exists").toBeTruthy();

    const aliceShared = new Uint8Array(ecdh("ed25519", alice.privateKey, bob.publicKey));
    const bobShared = new Uint8Array(ecdh("ed25519", bob.privateKey, alice.publicKey));
    t.expect(aliceShared.length).as("aliceShared secret size").toEqual(32);
    t.expect(bobShared.length).as("bobShared secret size").toEqual(32);
    t.expect(aliceShared.every((val, i) => val === bobShared[i]))
        .as("shared secrets equals")
        .toBeTruthy();
  });
}
export function testDefault() {
  describe("root hkdf", (t) => {
    const key = xcrypto.hkdf("sha256", "top secret", null, null, 64);
    t.expect(typeof(key) === 'object').as("key type").toBeTruthy();
    t.expect(key.byteLength).as("key length").toEqual(64);
  });

  describe("root hkdf: bad hashing algorithm", (t) => {
    const key = xcrypto.hkdf("sha999", "top secret", null, null, 64);
    t.expect(typeof(key) === "string").as("key error").toBeTruthy();
    t.expect(key).as("key error").toEqual('unsupported hash: sha999');
  });

  describe("root hkdf: bad bad keylen", (t) => {
    const key = xcrypto.hkdf("sha256", null, null, null, 8161);
    t.expect(typeof(key) === "string").as("key error").toBeTruthy();
    t.expect(key).as("key error").toEqual('invalid keylen: 8161, allowed range 1..8160');
  });

  describe("root pbkdf2", (t) => {
    const key = xcrypto.pbkdf2("top secret", null, 10000, 48, "sha256");
    t.expect(key.byteLength).as("key length").toEqual(48);
  });

  describe("root pbkdf2: bad hashing algorithm", (t) => {
    const key = xcrypto.pbkdf2("top secret", null, 10000, 48, "sha999");
    t.expect(typeof(key) === 'string').as("key type").toBeTruthy();
    t.expect(key).as("key error").toEqual('unsupported hash: sha999');
  });

  describe("root pbkdf2: bad keylen", (t) => {
    const key = xcrypto.pbkdf2("top secret", null, 10000, -1, "sha256");
    t.expect(typeof(key) === 'string').as("key type").toBeTruthy();
    t.expect(key).as("key error").toEqual('invalid keylen: -1, allowed range 1..∞');
  });

  describe("root generateKeyPair", (t) => {
    const pair = xcrypto.generateKeyPair("ed25519");
    t.expect(pair.publicKey.byteLength).as("public key length").toEqual(32);
    t.expect(pair.privateKey.byteLength).as("private key length").toEqual(64);
  });

  describe("root generateKeyPair with seed", (t) => {
    const pair = xcrypto.generateKeyPair("ed25519", xcrypto.pbkdf2("top secret", null, 10000, 32, "sha256"));
    t.expect(!!pair.publicKey).as("public key exists").toBeTruthy();
    t.expect(!!pair.privateKey).as("private key exists").toBeTruthy();
    t.expect(pair.publicKey.byteLength).as("public key length").toEqual(32);
    t.expect(pair.privateKey.byteLength).as("private key length").toEqual(64);
  });

  describe("root ecdh", (t) => {
    const alice = xcrypto.generateKeyPair("ed25519");
    const bob = xcrypto.generateKeyPair("ed25519");

    t.expect(!!alice.publicKey).as("alice public key exists").toBeTruthy();
    t.expect(!!alice.privateKey).as("alice private key exists").toBeTruthy();
    t.expect(!!bob.publicKey).as("bob public key exists").toBeTruthy();
    t.expect(!!bob.privateKey).as("bob private key exists").toBeTruthy();

    const aliceShared = new Uint8Array(ecdh("ed25519", alice.privateKey, bob.publicKey));
    const bobShared = new Uint8Array(ecdh("ed25519", bob.privateKey, alice.publicKey));
    t.expect(aliceShared.length).as("aliceShared secret size").toEqual(32);
    t.expect(bobShared.length).as("bobShared secret size").toEqual(32);
    t.expect(aliceShared.every((val, i) => val === bobShared[i]))
      .as("shared secrets equals")
      .toBeTruthy();
  });
}
