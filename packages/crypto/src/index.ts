import type { Crypto } from "@freesignal/protocol/interfaces";
import { CryptoConstructor } from "./crypto.js";

const sodium = (await import("libsodium-wrappers")).default;
const msgpack = await import("msgpackr");

await sodium.ready;

const crypto: Crypto = new CryptoConstructor(sodium, msgpack);

export default crypto;