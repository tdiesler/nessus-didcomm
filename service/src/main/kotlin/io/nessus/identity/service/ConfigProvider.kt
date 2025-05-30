package io.nessus.identity.service

import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addEnvironmentSource
import com.sksamuel.hoplite.addResourceSource

@OptIn(ExperimentalHoplite::class)
object ConfigProvider {

    val root = ConfigLoaderBuilder.default()
            .withExplicitSealedTypes()
            .addResourceSource("/application.conf")
            .addEnvironmentSource()
            .build().loadConfigOrThrow<RootConfig>().portal

    val oauthEndpointUri get() = "${requireServerConfig().baseUrl}/oauth"
    val issuerEndpointUri get() = "${requireServerConfig().baseUrl}/issuer"
    val holderEndpointUri get() = "${requireServerConfig().baseUrl}/holder"
    val verifierEndpointUri get() = "${requireServerConfig().baseUrl}/verifier"

    fun requireDatabaseConfig() : DatabaseConfig {
        return root.database ?: throw IllegalStateException("No 'database' config")
    }

    fun requireHolderConfig() : HolderConfig {
        return root.holder ?: throw IllegalStateException("No 'holder' config")
    }

    fun requireIssuerConfig() : IssuerConfig {
        return root.issuer ?: throw IllegalStateException("No 'issuer' config")
    }

    fun requireOAuthConfig() : OAuthConfig {
        return root.oauth ?: throw IllegalStateException("No 'oauth' config")
    }

    fun requireServerConfig() : ServerConfig {
        return root.server ?: throw IllegalStateException("No 'server' config")
    }

    fun requireServiceConfig() : ServiceConfig {
        return root.service ?: throw IllegalStateException("No 'service' config")
    }
}

data class RootConfig(
    val portal: PortalConfig,
)

data class PortalConfig(
    val server: ServerConfig?,
    val tls: TlsConfig?,
    val issuer: IssuerConfig?,
    val holder: HolderConfig?,
    val verifier: VerifierConfig?,
    val oauth: OAuthConfig?,
    val service: ServiceConfig?,
    val database: DatabaseConfig?,
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

data class IssuerConfig(
    val dummy: String?
)

data class HolderConfig(
    val userEmail: String,
    val userPassword: String,
)

data class VerifierConfig(
    val dummy: String?
)

data class OAuthConfig(
    val dummy: String?
)

data class ServiceConfig(
    val walletApiUrl: String,
    val issuerApiUrl: String,
    val verifierApiUrl: String,
    val demoWalletUrl: String,
)

data class DatabaseConfig(
    val jdbcUrl: String,
    val driverClassName: String,
    val username: String,
    val password: String,
)

