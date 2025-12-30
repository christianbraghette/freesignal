# FreeSignal Protocol

TypeScript primitives and a small reference implementation of the FreeSignal secure-messaging primitives.

This repository provides low-level building blocks: a lightweight key-exchange manager (X3DH-like), an in-memory keystore for testing, a double-ratchet style session manager, and small constructor helpers intended for building secure messaging clients or protocol tooling.

**Highlights**
- User factories and a test harness for peer handshakes and message exchange.
- Pure TypeScript implementation with a pluggable Crypto provider (see `@freesignal/crypto`).
- In-memory keystore reference implementation for testing: [src/keystore.ts](src/keystore.ts).

## Package

This package is published as `@freesignal/protocol` (see `package.json`). The library exports the primary constructors and helpers from `src/index.ts`:

- `UserFactory` — factory for creating `User` instances
- `UserConstructor` — low-level user constructor
- `InMemoryKeystoreFactory`, `InMemoryKeystore` — test keystore helpers
- `useConstructors` — convenience constructor helpers

## Installation

Install from npm:

```bash
npm install @freesignal/protocol
```

This library expects a compatible Crypto provider implementing the FreeSignal crypto interfaces — the test harness uses `@freesignal/crypto`.

## Quick start

The repository includes a small test/example in [src/test.ts](src/test.ts) which demonstrates creating two users, performing a handshake and exchanging messages.

Example (based on `src/test.ts`):

```ts
import crypto from "@freesignal/crypto";
import { UserFactory, InMemoryKeystoreFactory } from "@freesignal/protocol";

const userFactory = new UserFactory(new InMemoryKeystoreFactory(), crypto);
const alice = await userFactory.create();
const bob = await userFactory.create();


// Exchange pre-key bundle and complete handshake
const bundle = await alice.generatePreKeyBundle();
const message = await bob.handleIncomingPreKeyBundle(bundle);
await alice.handleIncomingPreKeyMessage(message);

// Encrypt / decrypt
const ciphertext = await alice.encrypt(bob.id, "Hello from Alice");
const plaintext = await bob.decrypt(alice.id, ciphertext);
console.log(plaintext);
```

This demonstrates how `UserFactory` composes the keystore, key-exchange manager and session manager to create a usable `User` object with `encrypt`, `decrypt`.

## API Overview

This package primarily exposes two constructors: `UserFactoryConstructor` and `UserConstructor` (re-exported from `src/index.ts`). Documentation below follows the runtime signatures implemented in `src/user.ts`.

- `UserFactoryConstructor` (constructor: `new UserFactoryConstructor(keyStoreFactory: KeyStoreFactory, crypto: Crypto)`)
  - `create(seed?: Bytes): Promise<User>` — create a `User` with a fresh identity or a deterministic seed. Uses `useConstructors` and the provided `Crypto` implementation to derive an identity and an in-memory `KeyStore` from the provided `KeyStoreFactory`.
  - `destroy(user: User): boolean` — optional cleanup; returns `true` if the factory removed internal references to the supplied `User` instance.

- `UserConstructor` (new UserConstructor(publicIdentity: PublicIdentity, keyStore: KeyStore, crypto: Crypto))
  - `publicIdentity: PublicIdentity` — the public identity supplied to the constructor.
  - `id: UserId` — getter for `publicIdentity.userId`.
  - `encrypt<T>(to: UserId | string, plaintext: T): Promise<Ciphertext>` — encrypt a payload for a recipient.
  - `decrypt<T>(ciphertext: Ciphertext | Bytes): Promise<DecryptResult<T>>` — decrypt an incoming ciphertext.
  - `generatePreKeyBundle(): Promise<PreKeyBundle>` — create a pre-key bundle for publication or delivery to a peer.
  - `handleIncomingPreKeyBundle(bundle: PreKeyBundle, associatedData?: Bytes): Promise<PreKeyMessage>` — process an incoming bundle and create the resulting session.
  - `handleIncomingPreKeyMessage(message: PreKeyMessage): Promise<Bytes | undefined>` — process an incoming pre-key message and create the resulting session.

## Build & test

The project compiles to `dist/` using TypeScript. The `package.json` scripts are:

```bash
# compile (run by `prepare` and `pretest`)
npm run prepare

# run tests (compiles first via pretest)
npm test
```

The test harness is `src/test.ts`; compiled output is `dist/test.js`.

## Contributing

- Keep changes focused and add tests for protocol behavior and edge cases.
- If you add features, include small examples or update `src/test.ts`.

## License

This project is licensed under `GPL-3.0-or-later`. See the `LICENSE` file in the repository root.

## Notes

- The in-memory keystore is a test/reference implementation only — for production use implement a durable `KeyStore`.
- The library is agnostic to the Crypto provider as long as it implements the expected `Crypto` FreeSignal interface from `@freesignal/interfaces`, you can use `@freesignal/crypto` as a reference implementation.

