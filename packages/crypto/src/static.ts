import type { Crypto } from '@freesignal/protocol/interfaces';
import { CryptoConstructor } from './crypto.js';
import sodium from "libsodium-wrappers";
import msgpack from '@msgpack/msgpack';

await sodium.ready;

const crypto: Crypto = new CryptoConstructor(sodium, msgpack);

export default crypto;