# @freesignal/crypto

Crypto utilities for the FreeSignal Protocol.

This package provides a small wrapper around libsodium and msgpack to expose hashing, key derivation, authenticated encryption (secretbox), ECDH, EdDSA signing, UUID helpers and various encoding utilities.

## Installation

Install from npm:

```bash
npm install @freesignal/crypto
```

The package depends on `libsodium-wrappers`, `@msgpack/msgpack` and `uuid` which are listed as dependencies and will be installed automatically.

## Quick Start

Import the default crypto instance, in wich libsodium-wrappers and msgpack are imported dinamiccaly:

```ts
import crypto from '@freesignal/crypto';

// Hash some data
const data = crypto.Utils.encodeUTF8('hello');
const digest = crypto.hash(data);

// Generate random bytes
const r = crypto.randomBytes(16);

// Use Box (secretbox) to encrypt/decrypt
const key = crypto.Box.keyLength ? crypto.randomBytes(crypto.Box.keyLength) : crypto.randomBytes(32);
const nonce = crypto.randomBytes(crypto.Box.nonceLength);
const cipher = crypto.Box.encrypt(data, nonce, key);
const plain = crypto.Box.decrypt(cipher, nonce, key);

// ECDH keypair
const { publicKey, secretKey } = crypto.ECDH.keyPair();
const shared = crypto.ECDH.scalarMult(secretKey, publicKey);

// EdDSA signing
const ed = crypto.EdDSA.keyPair();
const sig = crypto.EdDSA.sign(data, ed.secretKey);
const ok = crypto.EdDSA.verify(sig, data, ed.publicKey);

// HKDF example
const prk = crypto.hash(data);
const derived = crypto.hkdf(prk, new Uint8Array(32).fill(0), 'context', 32);

// UUID
const id = crypto.UUID.generate();
console.log(id.toString());

// Encoding utilities (short helpers are exported in `utils` file)
const b64 = crypto.Utils.encodeBase64URL('hello');
const decoded = crypto.Utils.decodeBase64URL(b64);
```

Is possible to static import libsodium-wrappers and msgpack using:

```ts
import crypto from '@freesignal/crypto/static';
```

In JS versions prior to ES2017 you need to use:

```ts
import { createCrypto } from '@freesignal/crypto/legacy';
```

## API Reference

Top-level default export: a ready-to-use `Crypto` instance.

Main methods and namespaces:

- `hash(message: Uint8Array, algorithm = 'blake2b') => Uint8Array`
  - Blake2b-based generic hash (32 bytes).
- `pwhash(keyLength, password, salt, opsLimit, memLimit) => Uint8Array`
  - Password-based key derivation (libsodium `crypto_pwhash`).
- `hmac(key, message, length = 32) => Uint8Array`
  - HMAC-like construct using BLAKE2b.
- `hkdf(key, salt, info?, length = 32) => Uint8Array`
  - HKDF implementation (extract+expand) built on BLAKE2b.
- `randomBytes(n) => Uint8Array`
  - Secure random byte generator.

Namespaces:

- `Box` (secretbox authenticated encryption)
  - `keyLength`, `nonceLength`
  - `encrypt(msg, nonce, key) => Uint8Array`
  - `decrypt(msg, nonce, key) => Uint8Array | undefined`

- `ECDH` (Curve25519 shared secrets)
  - `publicKeyLength`, `secretKeyLength`
  - `keyPair(secretKey?) => { publicKey, secretKey }`
  - `scalarMult(secretKey, publicKey) => Uint8Array`

- `EdDSA` (Ed25519 signing)
  - `publicKeyLength`, `secretKeyLength`, `signatureLength`
  - `keyPair(secretKey?) => { publicKey, secretKey }`
  - `keyPairFromSeed(seed) => { publicKey, secretKey }`
  - `sign(msg, secretKey) => Uint8Array`
  - `verify(signature, message, publicKey) => boolean`
  - `toSecretECDHKey(secretKey) => Uint8Array`
  - `toPublicECDHKey(publicKey) => Uint8Array`

- `UUID`
  - `generate()` returns an object with `toString()`, `toJSON()` and `bytes` (Uint8Array)
  - `stringify(arr, offset?)`, `parse(uuid)`

- `Utils` (encoding, conversion, msgpack)
  - `decodeUTF8`, `encodeUTF8`
  - `decodeBase64`, `encodeBase64`
  - `decodeBase64URL`, `encodeBase64URL`
  - `decodeHex`, `encodeHex`
  - `bytesToNumber`, `numberToBytes`
  - `compareBytes`, `concatBytes`
  - `encodeData`, `decodeData` (msgpack encode/decode)

Additionally, `src/utils.ts` re-exports convenient helper functions for the `Utils` namespace so you can:

```ts
import { encodeData, decodeData, encodeBase64 } from '@freesignal/crypto/utils';
```

## License

This project is released under the GNU GPL-3.0-or-later. See the `LICENSE` file for details.

## Contributing

Create issues or PRs on the repository: https://github.com/christianbraghette/freesignal-crypto

If you want me to expand the README with API signatures, inline examples for each method, or usage from browsers, tell me which parts to expand.