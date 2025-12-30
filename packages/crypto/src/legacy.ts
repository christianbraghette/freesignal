import type { Crypto } from "@freesignal/protocol/interfaces";

export async function createCrypto(): Promise<Crypto> {
    return (await import("./index.js")).default;
}
