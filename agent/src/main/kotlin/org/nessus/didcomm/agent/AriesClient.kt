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

import mu.KotlinLogging
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.logging.HttpLoggingInterceptor
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJsonPretty
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.wallet.Wallet
import org.slf4j.event.Level
import java.util.concurrent.TimeUnit

val JSON_TYPE: MediaType = "application/json; charset=utf-8".toMediaType()

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
    fun walletClient(wallet: Wallet, config: AgentConfiguration? = null, level: Level? = null): AriesClient {
        val loggingInterceptor = if (level != null) createHttpLoggingInterceptor(level) else null
        return walletClient(config, wallet, null, loggingInterceptor)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun walletClient(
        agentConfig: AgentConfiguration?,
        wallet: Wallet? = null,
        httpClient: OkHttpClient? = null,
        loggingInterceptor: HttpLoggingInterceptor? = null
    ): AriesClient {
        val config = agentConfig ?: AgentConfiguration.defaultConfiguration
        checkNotNull(config.adminUrl) { "No admin url in $config" }
        val auxHttpClient = httpClient ?: OkHttpClient.Builder()
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .connectTimeout(60, TimeUnit.SECONDS)
            .callTimeout(60, TimeUnit.SECONDS)
            .addInterceptor(loggingInterceptor ?: createHttpLoggingInterceptor(Level.TRACE))
            .build()
        return AriesClient(config.adminUrl, config.apiKey, wallet?.authToken, auxHttpClient)
    }

    private fun createHttpLoggingInterceptor(level: Level): HttpLoggingInterceptor {
        val log = KotlinLogging.logger {}
        fun log(spec: String, msg: String) {
            when(level) {
                Level.ERROR -> log.error(spec, msg)
                Level.WARN -> log.warn(spec, msg)
                Level.INFO -> log.info(spec, msg)
                Level.DEBUG -> log.debug(spec, msg)
                else -> log.trace(spec, msg)
            }
        }
        val interceptor = HttpLoggingInterceptor { msg: String ->
            if (log.isEnabledForLevel(level) && msg.isNotEmpty()) {
                if (msg.startsWith("{")) {
                    val json = msg.decodeJson()
                    log("{}", json.encodeJsonPretty(sorted = true))
                } else {
                    log("{}", msg)
                }
            }
        }
        interceptor.level = HttpLoggingInterceptor.Level.BODY
        interceptor.redactHeader("X-API-Key")
        interceptor.redactHeader("Authorization")
        return interceptor
    }
}

class AriesClient(val adminUrl: String, private val apiKey: String?, private val authToken: String?, private val httpClient: OkHttpClient) :
    org.hyperledger.aries.AriesClient(adminUrl, apiKey, authToken, httpClient) {

    val log = KotlinLogging.logger {}

    fun adminPost(path: String, body: Any, params: Map<String, Any>? = null, headers: Map<String, String>? = null): Response {
        return post(adminUrl + path, body, params, headers)
    }

    fun post(reqUrl: String, body: Any, params: Map<String, Any>? = null, headers: Map<String, String>? = null): Response {

        // Build the Request
        var actUrl = reqUrl
        if (params != null) {
            actUrl += "?"
            params.forEach { (k, v) -> actUrl += "$k=$v&"}
            actUrl = actUrl.dropLast(1)
        }
        val builder = Request.Builder().url(actUrl)

        // Add the headers
        headers?.filterKeys { it != "Content-Type" }?.forEach {
                (k, v) -> builder.header(k, v)
        }
        if (apiKey != null)
            builder.header("X-API-KEY", apiKey)
        if (authToken != null)
            builder.header("Authorization", "Bearer $authToken")

        val bodyJson = if (body is String) body else gson.toJson(body)
        val mediaType = headers?.get("Content-Type")?.toMediaType()
        val reqBody = bodyJson.toRequestBody(mediaType ?: JSON_TYPE)

        val req = builder.post(reqBody).build()
        val res = httpClient.newCall(req).execute()
        log.debug { "code=${res.code} message=${res.message}" }
        return res
    }
}
