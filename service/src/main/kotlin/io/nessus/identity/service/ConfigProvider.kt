package io.nessus.identity.service

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory

data class NessusConfig(
    val baseUrl: String,
    val walletApi: String,
    val issuerApi: String,
    val verifierApi: String,
    val userEmail: String,
    val userPassword: String,
    val authCallbackUrl: String,
    val dbConfig: DbConfig,
)

data class DbConfig(
    val jdbcUrl: String,
    val driverClassName: String,
    val username: String,
    val password: String,
)

object ConfigProvider {

    val mainConfig: Config = loadConfig().getConfig("proxy")
    val dbConfig: Config = mainConfig.getConfig("db")
    val waltConfig: Config = mainConfig.getConfig("walt")
    val baseUrl: String = mainConfig.getString("server.base_url")
    val config = NessusConfig(
        baseUrl = baseUrl,
        walletApi = waltConfig.getString("wallet-api"),
        issuerApi = waltConfig.getString("issuer-api"),
        verifierApi = waltConfig.getString("verifier-api"),
        userEmail = waltConfig.getString("user_email"),
        userPassword = waltConfig.getString("user_password"),
        authCallbackUrl = "${baseUrl}/auth-callback",
        dbConfig = DbConfig(
            jdbcUrl = dbConfig.getString("jdbcUrl"),
            driverClassName = dbConfig.getString("jdbcUrl"),
            username = dbConfig.getString("username"),
            password = dbConfig.getString("password"),
        )
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