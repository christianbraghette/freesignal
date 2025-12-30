import type { Bytes } from "@freesignal/protocol/interfaces";
import crypto from "./index.js";

/**
 * Decodes a Uint8Array into a UTF-8 string.
 *
 * @param array - The input byte array.
 * @returns The UTF-8 encoded string.
 */
const decodeUTF8 = (bytes: Bytes): string => crypto.Utils.decodeUTF8(bytes);

/**
 * Encodes a UTF-8 string into a Uint8Array.
 *
 * @param string - The input string.
 * @returns The resulting Uint8Array.
 */
const encodeUTF8 = (string: string): Bytes => crypto.Utils.encodeUTF8(string);

/**
 * Decodes a Uint8Array into a Base64 string.
 *
 * @param array - The input byte array.
 * @returns The Base64 encoded string.
 */
const decodeBase64 = (array: Bytes): string => crypto.Utils.decodeBase64(array);

/**
 * Encodes a Base64 string into a Uint8Array.
 *
 * @param string - The Base64 string.
 * @returns The decoded Uint8Array.
 */
const encodeBase64 = (string: string): Bytes => crypto.Utils.encodeBase64(string);

const decodeBase64URL = (array: Bytes): string => crypto.Utils.decodeBase64URL(array);
const encodeBase64URL = (string: string): Bytes => crypto.Utils.encodeBase64URL(string);

const decodeHex = (array: Bytes): string => crypto.Utils.decodeHex(array);
const encodeHex = (string: string): Bytes => crypto.Utils.encodeHex(string);

/**
 * Converts a Uint8Array into a number.
 *
 * @param array - The input byte array.
 * @returns The resulting number.
 */
const bytesToNumber = (bytes: Bytes, endian?: "big" | "little"): number => crypto.Utils.bytesToNumber(bytes, endian);

/**
 * Converts a number into a Uint8Array of specified length.
 *
 * @param number - The number to convert.
 * @param length - The desired output length.
 * @returns A Uint8Array representing the number.
 */
const numberToBytes = (value: number, length?: number, endian?: "big" | "little"): Bytes => crypto.Utils.numberToBytes(value, length, endian);

/**
 * Compare Uint8Arrays.
 * 
 * @param a - First Uint8Array to compare to.
 * @param b - Array to compare to the first one.
 * @param c - Arrays to compare to the first one.
 * @returns A boolean value.
 */
const compareBytes = (a: Bytes, b: Bytes, ...c: Bytes[]): boolean => crypto.Utils.compareBytes(a, b, ...c);

/**
 * Concat Uint8Arrays.
 * 
 * @param arrays - Uint8Array to concat.
 * @returns A Uint8Array
 */
const concatBytes = (...arrays: Bytes[]): Bytes => crypto.Utils.concatBytes(...arrays);

const encodeData = (data: any): Bytes => crypto.Utils.encodeData(data);
const decodeData = <T>(bytes: Bytes): T => crypto.Utils.decodeData<T>(bytes);


export {
    decodeUTF8,
    encodeUTF8,
    decodeBase64,
    encodeBase64,
    decodeBase64URL,
    encodeBase64URL,
    decodeHex,
    encodeHex,
    bytesToNumber,
    numberToBytes,
    compareBytes,
    concatBytes,
    encodeData,
    decodeData
};