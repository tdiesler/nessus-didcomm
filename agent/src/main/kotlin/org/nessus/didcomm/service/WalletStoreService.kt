/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.service

import id.walt.servicematrix.ServiceProvider
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.wallet.Wallet

class WalletStoreService: NessusBaseService() {
    override val implementation get() = serviceImplementation<WalletStoreService>()

    companion object: ServiceProvider {
        private val implementation = WalletStoreService()
        override fun getService() = implementation
    }

    private val walletStorage: MutableMap<String, Wallet> = mutableMapOf()
    private val didStorage: MutableMap<String, MutableList<Did>> = mutableMapOf()
    private val peerConnections: MutableMap<String, PeerConnectionStore> = mutableMapOf()

    val wallets get() = walletStorage.values.toList()
    fun wallets(predicate: (Wallet) -> Boolean): List<Wallet> {
        return walletStorage.values.filter { predicate.invoke(it) }.toList()
    }

    fun addWallet(wallet: Wallet) {
        walletStorage[wallet.id] = wallet
    }

    fun removeWallet(walletId: String): Wallet? {
        didStorage.remove(walletId)
        return walletStorage.remove(walletId)
    }

    fun getWallet(walletId: String): Wallet? {
        return walletStorage[walletId]
    }

    fun findByAlias(alias: String): Wallet? {
        return walletStorage.values.firstOrNull { w -> w.alias == alias }
    }

    fun findByVerkey(verkey: String): Wallet? {
        return didStorage
            .filter { (_, dids) -> dids.any { it.verkey == verkey} }
            .map { (wid, _) -> walletStorage[wid] }
            .firstOrNull()
    }

    fun addDid(walletId: String, did: Did) {
        check(walletStorage.contains(walletId)) { "Unknown walletId" }
        didStore(walletId).add(did)
    }

    fun listDids(walletId: String): List<Did> {
        check(walletStorage.contains(walletId)) { "Unknown walletId" }
        return didStore(walletId).toList()
    }

    fun addPeerConnection(walletId: String, con: PeerConnection) {
        peerConnectionStore(walletId).addConnection(con)
    }

    fun getPeerConnection(walletId: String, conId: String): PeerConnection? {
        return peerConnectionStore(walletId).getConnection(conId)
    }

    fun listPeerConnections(walletId: String): List<PeerConnection> {
        return peerConnectionStore(walletId).connections
    }

    fun removePeerConnections(walletId: String) {
        peerConnections.remove(walletId)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun didStore(walletId: String): MutableList<Did> {
        if (didStorage[walletId] == null) {
            didStorage[walletId] = mutableListOf()
        }
        return didStorage[walletId]!!
    }

    private fun peerConnectionStore(walletId: String): PeerConnectionStore {
        if (peerConnections[walletId] == null) {
            peerConnections[walletId] = PeerConnectionStore()
        }
        return peerConnections[walletId]!!
    }
}