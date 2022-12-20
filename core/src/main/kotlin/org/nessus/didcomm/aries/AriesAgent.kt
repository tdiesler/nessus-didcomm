package org.nessus.didcomm.aries

import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.api.multitenancy.WalletRecord
import java.net.MalformedURLException
import java.net.URL

class AgentConfiguration(val adminUrl: String?, val userUrl: String?, val apiKey: String?) {

    companion object {
        private val host = System.getenv("ACAPY_HOSTNAME") ?: "localhost"
        private val adminPort = System.getenv("ACAPY_ADMIN_PORT") ?: "8031"
        private val userPort = System.getenv("ACAPY_USER_PORT") ?: "8030"
        private val apiKey = System.getenv("ACAPY_ADMIN_API_KEY") ?: "adminkey"
        val defaultConfiguration= AgentConfigurationBuilder()
                .adminUrl(String.format("http://%s:%s", host, adminPort))
                .userUrl(String.format("http://%s:%s", host, userPort))
                .apiKey(apiKey)
                .build()
    }

    val webSocketUrl: String
        get() = try {
            val url = URL(adminUrl)
            String.format("ws://%s:%d/ws", url.host, url.port)
        } catch (ex: MalformedURLException) {
            throw IllegalArgumentException(ex)
        }

    override fun toString(): String {
        val reductedApiKey = if (apiKey != null) apiKey.substring(0, 4) + "..." else null
        return "AgentConfiguration [agentAdminUrl=$adminUrl, agentUserUrl=$userUrl, agentApiKey=$reductedApiKey]"
    }

    fun builder(): AgentConfigurationBuilder {
        return AgentConfigurationBuilder()
    }

    class AgentConfigurationBuilder {
        private var adminUrl: String? = null
        private var userUrl: String? = null
        private var apiKey: String? = null
        fun adminUrl(adminUrl: String?): AgentConfigurationBuilder {
            this.adminUrl = adminUrl
            return this
        }

        fun userUrl(userUrl: String?): AgentConfigurationBuilder {
            this.userUrl = userUrl
            return this
        }

        fun apiKey(apiKey: String?): AgentConfigurationBuilder {
            this.apiKey = apiKey
            return this
        }

        fun build(): AgentConfiguration {
            return AgentConfiguration(adminUrl, userUrl, apiKey)
        }
    }

    private fun getSystemEnv(key: String?, defaultValue: String?): String? {
        var value = System.getenv(key)
        if (value == null || value.isBlank() || value.isEmpty()) value = defaultValue
        return value
    }
}

object AriesClientFactory {
    /**
     * Create a client for the admin wallet
     */
    fun adminClient(): AriesClient {
        return createClient(AgentConfiguration.defaultConfiguration, null)
    }

    /**
     * Create a client for the admin wallet
     */
    fun adminClient(config: AgentConfiguration): AriesClient {
        return createClient(config, null)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun createClient(wallet: WalletRecord?): AriesClient {
        return createClient(AgentConfiguration.defaultConfiguration, wallet)
    }

    /**
     * Create a client for a multitenant wallet
     */
    fun createClient(config: AgentConfiguration, wallet: WalletRecord?): AriesClient {
        return AriesClient.builder()
            .url(config.adminUrl)
            .apiKey(config.apiKey)
            .bearerToken(wallet?.token)
            .build()
    }
}
