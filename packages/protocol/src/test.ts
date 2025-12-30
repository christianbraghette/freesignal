import { decodeBase64 } from "@freesignal/crypto/utils";
import { UserFactory, InMemoryKeystoreFactory } from "./index.js";
import crypto from "@freesignal/crypto";
import type { Bytes } from "./interfaces.ts";

const userFactory = new UserFactory(new InMemoryKeystoreFactory(crypto), crypto);

const alice = await userFactory.create();
const bob = await userFactory.create();

const bundle = await alice.generatePreKeyBundle();
const message = await bob.handleIncomingPreKeyBundle(bundle);
await alice.handleIncomingPreKeyMessage(message);
console.log("Handshaked");

const cyphertext = await bob.encrypt(alice.id, "Testone");
console.log((await alice.decrypt(cyphertext)).data);

console.log("Starting big test...");

setTimeout(async () => {
    console.log("Big Test started!");
    const messages = await Promise.all(Array(2950).fill(0).map(() => alice.encrypt(bob.id, crypto.randomBytes(64))));
    console.log("2950 encrypted messages");
    await Promise.all(messages.map(async (message) => console.log(decodeBase64((await bob.decrypt<Bytes>(message)).data))));
    console.log("2950 decrypted messages");
}, 1000)