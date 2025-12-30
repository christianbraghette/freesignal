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

import type { KeyExchangeManager, KeyStore, PreKeyBundle, PublicIdentity, SessionManager, User, UserFactory, Crypto, Bytes, Ciphertext, UserId, KeyStoreFactory, PreKeyMessage, DecryptResult } from "./interfaces.ts";
import { KeyExchangeManagerConstructor } from "./keyexchange.js";
import { SessionManagerConstructor } from "./session.js";
import { useConstructors } from "./constructors.js";

export class UserFactoryConstructor implements UserFactory {
    readonly #objestStore = new WeakSet();

    constructor(private readonly keyStoreFactory: KeyStoreFactory, private readonly crypto: Crypto) { }

    public async create(seed?: Bytes): Promise<User> {
        const { IdentityConstructor } = useConstructors(this.crypto);

        const identity = IdentityConstructor.from((seed ? this.crypto.EdDSA.keyPairFromSeed(seed) : this.crypto.EdDSA.keyPair()).secretKey);
        const user = new UserConstructor(identity, await this.keyStoreFactory.createStore(identity), this.crypto);
        this.#objestStore.add(user);
        return user;
    };

    public destroy(user: User): boolean {
        return this.#objestStore.delete(user);
    }
}

export class UserConstructor implements User {
    readonly #sessionManager: SessionManager;
    readonly #keyExchangeManager: KeyExchangeManager;

    constructor(public readonly publicIdentity: PublicIdentity, keyStore: KeyStore, private readonly crypto: Crypto) {
        this.#sessionManager = new SessionManagerConstructor(keyStore, crypto);
        this.#keyExchangeManager = new KeyExchangeManagerConstructor(publicIdentity, keyStore, crypto);
    }

    public get id(): UserId {
        return this.publicIdentity.userId;
    }

    public encrypt<T>(to: UserId | string, plaintext: T): Promise<Ciphertext> {
        return this.#sessionManager.encrypt(to, this.crypto.Utils.encodeData(plaintext));
    }

    public async decrypt<T>(ciphertext: Ciphertext | Bytes): Promise<DecryptResult<T>> {
        return await this.#sessionManager.decrypt(ciphertext);
    }

    public generatePreKeyBundle(): Promise<PreKeyBundle> {
        return this.#keyExchangeManager.createPreKeyBundle();
    }

    public async handleIncomingPreKeyBundle(bundle: PreKeyBundle, associatedData?: Bytes): Promise<PreKeyMessage> {
        const { session, message } = await this.#keyExchangeManager.processPreKeyBundle(bundle, associatedData);
        await this.#sessionManager.createSession(session);
        return message;
    }

    public async handleIncomingPreKeyMessage(message: PreKeyMessage): Promise<Bytes | undefined> {
        const { session, associatedData } = await this.#keyExchangeManager.processPreKeyMessage(message);
        await this.#sessionManager.createSession(session);
        return associatedData;
    }

}