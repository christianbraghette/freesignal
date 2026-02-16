/**
 * FreeSignal Protocol
 * 
 * Copyright (C) 2025  Christian Braghette
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import type sodium from 'libsodium-wrappers';
import type msgpack from '@msgpack/msgpack';
import type { Crypto } from '@freesignal/protocol/interfaces';
import { stringify, parse, v4 as uuidv4 } from 'uuid';

type Sodium = typeof sodium;
type Msgpack = typeof msgpack;

abstract class SodiumCrypto {
    constructor(protected readonly sodium: Sodium) { }
}

export class CryptoConstructor extends SodiumCrypto implements Crypto {

    constructor(protected readonly sodium: Sodium, protected readonly msgpack: Msgpack) {
        super(sodium);
    }

    public hash(message: Uint8Array, algorithm: CryptoConstructor.HashAlgorithms = 'blake2b'): Uint8Array {
        try {
            if (algorithm !== 'blake2b')
                throw new Error("Algorithm not supported");
            return this.sodium.crypto_generichash(32, message, null);
        } catch (error) {
            throw error;
        }
    }

    public pwhash(keyLength: number, password: string | Uint8Array, salt: Uint8Array, opsLimit: number, memLimit: number): Uint8Array {
        try {
            return this.sodium.crypto_pwhash(keyLength, password, salt, opsLimit, memLimit, this.sodium.crypto_pwhash_ALG_DEFAULT, 'uint8array')
        } catch (error) {
            throw error;
        }
    }

    public hmac(key: Uint8Array, message: Uint8Array, length: number = 32, algorithm: CryptoConstructor.HmacAlgorithms = 'blake2b') {
        try {
            if (algorithm !== 'blake2b')
                throw new Error("Algorithm not supported");
            return this.sodium.crypto_generichash(length, message, key);
        } catch (error) {
            throw error;
        }
    }

    public hkdf(key: Uint8Array, salt: Uint8Array, info: Uint8Array | string, length: number = 32): Uint8Array {
        try {
            if (typeof info === 'string')
                info = this.sodium.from_string(info);

            const hashLen = 32; // BLAKE2b-256

            if (length > 255 * hashLen)
                throw new Error('HKDF output too large');

            const prk = this.sodium.crypto_generichash(
                hashLen,
                key,
                salt
            );

            let temp: Uint8Array = new Uint8Array();
            const n = Math.ceil(length / hashLen);
            const okm = new Uint8Array(length);

            let input = new Uint8Array(info.length + 1);
            for (let i = 1, offset = 0; i <= n; i++, offset += hashLen) {
                const inputLen = temp.length + info.length + 1;

                if (input.length < inputLen)
                    input = new Uint8Array(inputLen);

                input.set(temp, 0);
                input.set(info, temp.length);
                input[temp.length + info.length] = i;

                temp = this.sodium.crypto_generichash(hashLen, input, prk);

                okm.set(temp.subarray(0, Math.min(hashLen, length - offset)), offset);
            }

            return okm;
        } catch (error) {
            throw error;
        }
    }

    readonly Box = new BoxConstructor(this.sodium);
    readonly ECDH = new ECDHConstructor(this.sodium);
    readonly EdDSA = new EdDSAConstructor(this.sodium);
    readonly UUID = new UUIDConstructor(this.sodium);
    readonly Utils = new UtilsConstructor(this.sodium, this.msgpack);

    public randomBytes(n: number): Uint8Array {
        try {
            return this.sodium.randombytes_buf(n);
        } catch (error) {
            throw error;
        }
    };
}
export namespace CryptoConstructor {
    export type HashAlgorithms = 'blake2b';
    export type HmacAlgorithms = 'blake2b';

    export type KeyPair = Crypto.KeyPair;
}

class BoxConstructor extends SodiumCrypto implements Crypto.Box {
    public readonly keyLength = this.sodium.crypto_secretbox_KEYBYTES;
    public readonly nonceLength = this.sodium.crypto_secretbox_NONCEBYTES;

    public encrypt(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
        try {
            return this.sodium.crypto_secretbox_easy(msg, nonce, key);
        } catch (error) {
            throw error;
        }
    }

    public decrypt(msg: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | undefined {
        try {
            return this.sodium.crypto_secretbox_open_easy(msg, nonce, key);
        } catch {
            return undefined;
        }
    }
}

class ECDHConstructor extends SodiumCrypto implements Crypto.ECDH {
    public readonly publicKeyLength = this.sodium.crypto_scalarmult_BYTES;
    public readonly secretKeyLength = this.sodium.crypto_scalarmult_SCALARBYTES;

    public keyPair(secretKey?: Uint8Array): CryptoConstructor.KeyPair {
        try {
            if (secretKey) {
                const publicKey = this.sodium.crypto_scalarmult_base(secretKey);
                return { publicKey, secretKey };
            }
            const keys = this.sodium.crypto_box_keypair()
            return { publicKey: keys.publicKey, secretKey: keys.privateKey };
        } catch (error) {
            throw error;
        }
    }

    public scalarMult(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
        try {
            return this.sodium.crypto_scalarmult(secretKey, publicKey);
        } catch (error) {
            throw error;
        }
    };
}

class EdDSAConstructor extends SodiumCrypto implements Crypto.EdDSA {
    readonly publicKeyLength = this.sodium.crypto_sign_PUBLICKEYBYTES;
    readonly secretKeyLength = this.sodium.crypto_sign_SECRETKEYBYTES;
    readonly signatureLength = this.sodium.crypto_sign_BYTES;

    public keyPair(secretKey?: Uint8Array): Crypto.KeyPair {
        try {
            if (secretKey)
                if (secretKey.length !== this.secretKeyLength)
                    throw new Error("Wrong secretKey length");
                else
                    return { secretKey: secretKey, publicKey: secretKey.slice(this.secretKeyLength - this.publicKeyLength) }
            const key = this.sodium.crypto_sign_keypair('uint8array');
            return { secretKey: key.privateKey, publicKey: key.publicKey };
        } catch (error) {
            throw error;
        }
    }

    public keyPairFromSeed(seed: Uint8Array): Crypto.KeyPair {
        try {
            seed = this.sodium.crypto_generichash(this.sodium.crypto_sign_SEEDBYTES, seed, null);
            const keys = this.sodium.crypto_sign_seed_keypair(seed);
            return { secretKey: keys.privateKey, publicKey: keys.publicKey };
        } catch (error) {
            throw error;
        }
    }

    public sign(msg: Uint8Array, secretKey: Uint8Array): Uint8Array {
        try {
            return this.sodium.crypto_sign_detached(msg, secretKey);
        } catch (error) {
            throw error;
        }
    }

    public verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
        try {
            return this.sodium.crypto_sign_verify_detached(signature, message, publicKey);
        } catch (error) {
            throw error;
        }
    }

    public toSecretECDHKey(secretKey: Uint8Array): Uint8Array {
        return this.sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey);
    }

    public toPublicECDHKey(publicKey: Uint8Array): Uint8Array {
        return this.sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey);
    }

}

class UUIDv4 {
    private value: string;

    constructor() {
        this.value = uuidv4();
    }

    toString(): string {
        return this.value;
    }

    toJSON(): string {
        return this.value;
    }

    get bytes(): Uint8Array {
        return parse(this.value);
    }
}

class UUIDConstructor extends SodiumCrypto implements Crypto.UUID {
    generate(): UUIDv4 {
        return new UUIDv4();
    }

    stringify(arr: Uint8Array, offset?: number): string {
        return stringify(arr, offset);
    }

    parse(uuid: string): Uint8Array {
        return parse(uuid);
    }
}

class UtilsConstructor extends SodiumCrypto implements Crypto.Utils {

    constructor(protected readonly sodium: Sodium, protected readonly msgpack: Msgpack) {
        super(sodium);
    }

    public decodeUTF8(array: Uint8Array): string {
        return this.sodium.to_string(array);
    }

    public encodeUTF8(string: string): Uint8Array {
        return this.sodium.from_string(string);
    }

    public decodeBase64(array: Uint8Array): string {
        return this.sodium.to_base64(array, this.sodium.base64_variants.ORIGINAL);
    }
    public encodeBase64(string: string): Uint8Array {
        return this.sodium.from_base64(string, this.sodium.base64_variants.ORIGINAL);
    }

    public decodeBase64URL(array: Uint8Array): string {
        return this.sodium.to_base64(array, this.sodium.base64_variants.URLSAFE_NO_PADDING);
    }

    public encodeBase64URL(string: string): Uint8Array {
        return this.sodium.from_base64(string, this.sodium.base64_variants.URLSAFE_NO_PADDING);
    }

    public decodeHex(array: Uint8Array): string {
        return this.sodium.to_hex(array);
    }

    public encodeHex(string: string): Uint8Array {
        return this.sodium.from_hex(string);
    }

    public bytesToNumber(array: Uint8Array, endian: 'big' | 'little' = 'little'): number {
        const outArray = new Uint8Array(8).fill(0);
        if (endian === 'big')
            array = array.reverse();
        outArray.set(array);
        return Number(new BigUint64Array(outArray.buffer)[0]);
    }

    public numberToBytes(number: number, length?: number, endian: 'big' | 'little' = 'little'): Uint8Array {
        const bigInt = BigInt(number);
        let array = new Uint8Array(new BigUint64Array(1).fill(bigInt).buffer);
        if (length) {
            array = array.slice(0, length);
        }
        return endian === 'big' ? array.reverse() : array;
    }

    public compareBytes(a: Uint8Array, b: Uint8Array, ...c: Uint8Array[]): boolean {
        const arrays = new Array<Uint8Array>().concat(a, b, ...c).filter(array => array !== undefined && array.length > 0);
        if (arrays.length < 2) return false;
        return arrays.every(b => this.sodium.memcmp(a, b));
    }

    public concatBytes(...arrays: Uint8Array[]) {
        const length = arrays.reduce((count, array) => count + array.length, 0);

        const out = new Uint8Array(length);

        let offset = 0;
        for (const array of arrays) {
            out.set(array, offset);
            offset += array.length;
        }

        return out
    }

    public encodeData(obj: any) {
        return this.msgpack.encode(obj);
    }

    public decodeData<T>(array: Uint8Array): T {
        return this.msgpack.decode(array) as any;
    }
}