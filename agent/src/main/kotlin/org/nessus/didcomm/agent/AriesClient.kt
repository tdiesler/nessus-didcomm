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

import com.google.gson.JsonObject
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

class AgentConfiguration private constructor(
    val adminUrl: String?,
    val userUrl: String?,
    val apiKey: String?
) {
    companion object {
        private val host = System.getenv("ACAPY_HOSTNAME") ?: "localhost"
        private val adminPort = System.getenv("ACAPY_ADMIN_PORT") ?: "8031"
        private val userPort = System.getenv("ACAPY_USER_PORT") ?: "8030"
        private val apiKey = System.getenv("ACAPY_ADMIN_API_KEY") ?: "adminkey"
        val defaultConfiguration = builder()
                .adminUrl(String.format("http://%s:%s", host, adminPort))
                .userUrl(String.format("http://%s:%s", host, userPort))
                .apiKey(apiKey)
                .build()

        fun builder(): Builder {
            return Builder()
        }
    }

    override fun toString(): String {
        val redactedApiKey = if (apiKey != null) apiKey.substring(0, 4) + "..." else null
        return "AgentConfiguration [agentAdminUrl=$adminUrl, agentUserUrl=$userUrl, agentApiKey=$redactedApiKey]"
    }

    data class Builder(
            private var adminUrl: String? = null,
            private var userUrl: String? = null,
            private var apiKey: String? = null
    ) {

        fun adminUrl(adminUrl: String) = apply { this.adminUrl = adminUrl }
        fun userUrl(userUrl: String) = apply { this.userUrl = userUrl }
        fun apiKey(apiKey: String) = apply { this.apiKey = apiKey }
        fun build() = AgentConfiguration(adminUrl, userUrl, apiKey)
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

class AriesClient(val adminUrl: String, private val apiKey: String?, private val bearerToken: String?, private val httpClient: OkHttpClient) :
    org.hyperledger.aries.AriesClient(adminUrl, apiKey, bearerToken, httpClient) {

    val log = KotlinLogging.logger {}

    fun post(path: String, body: Any, options: Map<String, Any>? = null): Response {

        // Build the Request
        var reqUrl = adminUrl + path
        if (options != null) {
            reqUrl += "?"
            options.forEach {(k, v) -> reqUrl += "$k=$v&"}
            reqUrl = reqUrl.dropLast(1)
        }
        val builder = Request.Builder().url(reqUrl)
        if (apiKey != null)
            builder.header("X-API-KEY", apiKey)
        if (bearerToken != null)
            builder.header("Authorization", "Bearer $bearerToken")
        val bodyJson = if (body is String && body.trim().startsWith("{")) {
            val jsonObj = gson.fromJson(body, JsonObject::class.java)
            gson.toJson(jsonObj)
        } else {
            gson.toJson(body)
        }
        val req = builder.post(bodyJson.toRequestBody(JSON_TYPE)).build()
        val res = httpClient.newCall(req).execute()
        log.debug { "code=${res.code} message=${res.message}" }
        return res
    }
}
