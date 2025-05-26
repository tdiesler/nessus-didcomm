package org.nessus.identity.proxy

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import org.nessus.identity.proxy.OpenId4VCService.Companion.loadConfig

data class NessusConfig(
    val baseUrl: String,
    val walletApi: String,
    val issuerApi: String,
    val verifierApi: String,
    val userEmail: String,
    val userPassword: String,
    val authCallbackUrl: String,
)

object ConfigProvider {

    val mainConfig: Config = loadConfig().getConfig("proxy")
    val baseUrl = mainConfig.getString("server.base_url")
    val config = NessusConfig(
        baseUrl = baseUrl,
        walletApi = mainConfig.getString("walt.wallet-api"),
        issuerApi = mainConfig.getString("walt.issuer-api"),
        verifierApi = mainConfig.getString("walt.verifier-api"),
        userEmail = mainConfig.getString("walt.user_email"),
        userPassword = mainConfig.getString("walt.user_password"),
        authCallbackUrl = "${baseUrl}/auth-callback",
    )

    private fun loadConfig(): Config {

        val envVars = System.getenv()
        val baseCfg = ConfigFactory.load()
        val mergedCfg = mutableMapOf<String, String>()

        // Recursively collect all keys in base config
        fun flatten(prefix: String, cfg: Config) {
            for (entry in cfg.entrySet()) {
                val fullKey = if (prefix.isEmpty()) entry.key else "$prefix.${entry.key}"
                val envKey = fullKey.uppercase().replace('.', '_').replace('-', '_')
                mergedCfg[fullKey] = envVars[envKey] ?: baseCfg.getValue(fullKey).unwrapped().toString()
            }
        }
        flatten("", baseCfg)
        return ConfigFactory.parseMap(mergedCfg)
    }
}