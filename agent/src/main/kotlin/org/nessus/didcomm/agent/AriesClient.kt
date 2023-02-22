/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
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
package org.nessus.didcomm.agent

import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.logging.HttpLoggingInterceptor
import org.nessus.didcomm.service.HttpService
import org.nessus.didcomm.service.HttpService.HttpClient.Companion.createHttpLoggingInterceptor
import org.nessus.didcomm.wallet.AcapyWallet
import org.slf4j.event.Level

data class AgentConfiguration(
    val hostname: String,
    val adminPort: String,
    val userPort: String,
    val apiKey: String
) {
    companion object {
        private val defaultHostname = System.getenv("ACAPY_HOSTNAME") ?: "localhost"
        private val defaultAdminPort = System.getenv("ACAPY_ADMIN_PORT") ?: "8031"
        private val defaultUserPort = System.getenv("ACAPY_USER_PORT") ?: "8030"
        private val defaultApiKey = System.getenv("ACAPY_ADMIN_API_KEY") ?: "adminkey"
        fun agentConfiguration(options: Map<String, Any>): AgentConfiguration {
            val hostname = options["ACAPY_HOSTNAME"] as? String ?: defaultHostname
            val adminPort = options["ACAPY_ADMIN_PORT"] as? String ?: defaultAdminPort
            val userPort = options["ACAPY_USER_PORT"] as? String ?: defaultUserPort
            val apiKey = options["ACAPY_ADMIN_API_KEY"] as? String ?: defaultApiKey
            return AgentConfiguration(hostname, adminPort, userPort, apiKey)
        }
        val defaultConfiguration get() = agentConfiguration(mapOf())
    }

    val adminUrl get() = "http://$hostname:$adminPort"
    val userUrl get() = "http://$hostname:$userPort"
    val wsUrl get() = "ws://$hostname:$adminPort/ws"

    override fun toString(): String {
        val redactedApiKey = apiKey.substring(0, 4) + "..."
        return "AgentConfiguration [agentAdminUrl=$adminUrl, agentUserUrl=$userUrl, agentApiKey=$redactedApiKey]"
    }
}

object AriesClientFactory {

    /**
     * Create a client for the admin wallet
     */
    fun adminClient(config: AgentConfiguration? = null, level: Level? = null): AriesClient {
        val loggingInterceptor = if (level != null) createHttpLoggingInterceptor(level) else null
        return walletClient(config, null, null, loggingInterceptor)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun walletClient(wallet: AcapyWallet, config: AgentConfiguration? = null, level: Level? = null): AriesClient {
        val loggingInterceptor = if (level != null) createHttpLoggingInterceptor(level) else null
        return walletClient(config, wallet, null, loggingInterceptor)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun walletClient(
        agentConfig: AgentConfiguration?,
        wallet: AcapyWallet? = null,
        httpClient: OkHttpClient? = null,
        loggingInterceptor: HttpLoggingInterceptor? = null
    ): AriesClient {
        val config = agentConfig ?: AgentConfiguration.defaultConfiguration
        checkNotNull(config.adminUrl) { "No admin url in $config" }
        return AriesClient(config.adminUrl, config.apiKey, wallet?.authToken, loggingInterceptor, httpClient)
    }

}

class AriesClient(
    val adminUrl: String,
    private val apiKey: String?,
    private val authToken: String?,
    private val loggingInterceptor: HttpLoggingInterceptor? = null,
    private val httpClient: OkHttpClient? = null):
    org.hyperledger.aries.AriesClient(adminUrl, apiKey, authToken, httpClient) {

    private val httpService get() = HttpService.getService()

    fun adminPost(path: String, body: Any, params: Map<String, Any>? = null, headers: Map<String, String> = mapOf()): Response {
        val mutableHeaders = headers.toMutableMap()
        if (apiKey != null)
            mutableHeaders["X-API-KEY"] = apiKey
        if (authToken != null)
            mutableHeaders["Authorization"] = "Bearer $authToken"
        val httpClient = httpService.httpClient(loggingInterceptor, httpClient)
        return httpClient.post(adminUrl + path, body, params, mutableHeaders.toMap())
    }
}

