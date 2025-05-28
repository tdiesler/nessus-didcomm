package io.nessus.identity.service

import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addEnvironmentSource
import com.sksamuel.hoplite.addResourceSource

@OptIn(ExperimentalHoplite::class)
object ConfigProvider {

    val portalConfig = ConfigLoaderBuilder.default()
            .withExplicitSealedTypes()
            .addResourceSource("/application.conf")
            .addEnvironmentSource()
            .build().loadConfigOrThrow<RootConfig>().portal
    val serverConfig = portalConfig.server
    val tlsConfig = portalConfig.tls
    val oauthConfig = portalConfig.oauth
    val holderConfig = portalConfig.holder
    val databaseConfig = portalConfig.database

    fun requireDatabaseConfig() : DatabaseConfig {
        return portalConfig.database ?: throw IllegalStateException("No 'database' config")
    }

    fun requireHolderConfig() : HolderConfig {
        return portalConfig.holder ?: throw IllegalStateException("No 'holder' config")
    }

    fun requireOAuthConfig() : OAuthConfig {
        return portalConfig.oauth ?: throw IllegalStateException("No 'oauth' config")
    }

    fun requireServerConfig() : ServerConfig {
        return portalConfig.server ?: throw IllegalStateException("No 'server' config")
    }
}

data class RootConfig(
    val portal: PortalConfig,
)

data class PortalConfig(
    val server: ServerConfig? = null,
    val tls: TlsConfig? = null,
    val holder: HolderConfig? = null,
    val oauth: OAuthConfig? = null,
    val database: DatabaseConfig? = null,
)

data class ServerConfig(
    val host: String,
    val port: Int,
    val baseUrl: String,
)

data class TlsConfig(
    val enabled: Boolean,
    val keyAlias: String,
    val keystoreFile: String,
    val keystorePassword: String,
)

data class HolderConfig(
    val walletApi: String,
    val userEmail: String,
    val userPassword: String,
)

data class OAuthConfig(
    val endpointUrl: String,
)

data class DatabaseConfig(
    val jdbcUrl: String,
    val driverClassName: String,
    val username: String,
    val password: String,
)

