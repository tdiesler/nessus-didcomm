package org.nessus.didcomm.agent.aries

import com.google.gson.JsonSyntaxException
import mu.KotlinLogging
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.config.GsonConfig
import org.nessus.didcomm.wallet.NessusWallet
import org.slf4j.event.Level
import java.util.concurrent.TimeUnit

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
        val reductedApiKey = if (apiKey != null) apiKey.substring(0, 4) + "..." else null
        return "AgentConfiguration [agentAdminUrl=$adminUrl, agentUserUrl=$userUrl, agentApiKey=$reductedApiKey]"
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
        val auxConfig = config ?: AgentConfiguration.defaultConfiguration
        return walletClient(auxConfig, level=level)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun walletClient(config: AgentConfiguration? = null, wallet: NessusWallet? = null, level: Level? = null): AriesClient {
        val auxConfig = config ?: AgentConfiguration.defaultConfiguration
        val loggingInterceptor = if (level != null) createHttpLoggingInterceptor(level) else null
        return walletClient(auxConfig, wallet, null, loggingInterceptor)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun walletClient(
        config: AgentConfiguration,
        wallet: NessusWallet? = null,
        httpClient: OkHttpClient? = null,
        loggingInterceptor: HttpLoggingInterceptor? = null
    ): AriesClient {
        val auxHttpClient = httpClient ?: OkHttpClient.Builder()
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .connectTimeout(60, TimeUnit.SECONDS)
            .callTimeout(60, TimeUnit.SECONDS)
            .addInterceptor(loggingInterceptor ?: createHttpLoggingInterceptor(Level.TRACE))
            .build()
        return AriesClient.builder()
            .url(config.adminUrl)
            .apiKey(config.apiKey)
            .bearerToken(wallet?.accessToken)
            .client(auxHttpClient)
            .build()
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
                    try {
                        val json: Any = gson.fromJson<Any>(msg, Any::class.java)
                        log("\n{}", pretty.toJson(json))
                    } catch (e: JsonSyntaxException) {
                        log("{}", msg)
                    }
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
