import crypto from "./index.js";
import { decodeData, encodeData } from "./utils.js";

console.log(decodeData(encodeData("Dio")));
console.log(crypto.hkdf(crypto.hash(encodeData("Dio")), new Uint8Array(32).fill(0), "TestKey", 230));