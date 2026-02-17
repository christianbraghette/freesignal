import type { Crypto } from '@freesignal/protocol/interfaces';
import { CryptoConstructor } from './crypto.js';
import sodium from "libsodium-wrappers";
import * as msgpack from 'msgpackr';

await sodium.ready;

const crypto: Crypto = new CryptoConstructor(sodium, msgpack);

export default crypto;