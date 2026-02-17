import type { Crypto } from "@freesignal/protocol/interfaces";
import { CryptoConstructor } from "./crypto.js";

const sodium = (await import("libsodium-wrappers")).default;
const msgpackModule = (await import("@msgpack/msgpack"));

await sodium.ready;

const crypto: Crypto = new CryptoConstructor(sodium, msgpackModule.default || msgpackModule);

export default crypto;