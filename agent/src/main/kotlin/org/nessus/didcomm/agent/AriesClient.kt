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

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import mu.KotlinLogging
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import org.hyperledger.aries.api.exception.AriesException
import org.hyperledger.aries.config.GsonConfig
import org.nessus.didcomm.wallet.NessusWallet
import org.slf4j.event.Level
import java.util.concurrent.TimeUnit

val JSON_TYPE: MediaType = "application/json; charset=utf-8".toMediaType()

private val gson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .create()
private val prettyGson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .setPrettyPrinting()
    .create()

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
        val defaultConfiguration: AgentConfiguration = builder()
                .adminUrl(String.format("http://%s:%s", host, adminPort))
                .userUrl(String.format("http://%s:%s", host, userPort))
                .apiKey(apiKey)
                .build()

        fun builder(): AgentConfigurationBuilder {
            return AgentConfigurationBuilder()
        }
    }

    override fun toString(): String {
        val redactedApiKey = if (apiKey != null) apiKey.substring(0, 4) + "..." else null
        return "AgentConfiguration [agentAdminUrl=$adminUrl, agentUserUrl=$userUrl, agentApiKey=$redactedApiKey]"
    }

    class AgentConfigurationBuilder {

        private var adminUrl: String? = null
        private var userUrl: String? = null
        private var apiKey: String? = null

        fun adminUrl(adminUrl: String): AgentConfigurationBuilder {
            this.adminUrl = adminUrl
            return this
        }

        fun userUrl(userUrl: String): AgentConfigurationBuilder {
            this.userUrl = userUrl
            return this
        }

        fun apiKey(apiKey: String): AgentConfigurationBuilder {
            this.apiKey = apiKey
            return this
        }

        fun build(): AgentConfiguration {
            return AgentConfiguration(adminUrl, userUrl, apiKey)
        }
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
    fun walletClient(wallet: NessusWallet, config: AgentConfiguration? = null, level: Level? = null): AriesClient {
        val loggingInterceptor = if (level != null) createHttpLoggingInterceptor(level) else null
        return walletClient(config, wallet, null, loggingInterceptor)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun walletClient(
        config: AgentConfiguration?,
        wallet: NessusWallet? = null,
        httpClient: OkHttpClient? = null,
        loggingInterceptor: HttpLoggingInterceptor? = null
    ): AriesClient {
        val config = config ?: AgentConfiguration.defaultConfiguration
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
        val gson = GsonConfig.defaultConfig()
        val pretty = GsonConfig.prettyPrinter()
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
                    val json = gson.fromJson(msg, Any::class.java)
                    log("{}", pretty.toJson(json))
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

class AriesClient(private val url: String?, private val apiKey: String?, private val bearerToken: String?, private val httpClient: OkHttpClient) :
    org.hyperledger.aries.AriesClient(url, apiKey, bearerToken, httpClient) {

    val log = KotlinLogging.logger {}

    fun post(path: String, body: Any, options: Map<String, Any>? = null): Map<String, Any> {

        // Build the Request
        var reqUrl = url + path
        if (options != null) {
            reqUrl += "?"
            options.forEach {(k, v) -> reqUrl += "$k=$v"}
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

        // Call the Aries endpoint
        val res = httpClient.newCall(req).execute()
        val resBody = res.body?.string() ?: ""

        // Fail if not success
        if (!res.isSuccessful) {
            log.error("code={} message={}\nbody={}", res.code, res.message, resBody)
            throw AriesException(res.code, res.message + "\n" + resBody)
        }

        // Return a Json Map
        val resObj: MutableMap<String, Any> = mutableMapOf()
        gson.fromJson(resBody, MutableMap::class.java).forEach { en ->
            resObj[en.key.toString()] = en.value!!
        }
        return resObj.toMap()
    }
}
