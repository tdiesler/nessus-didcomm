package io.nessus.identity.service

import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addEnvironmentSource
import com.sksamuel.hoplite.addResourceSource
import kotlinx.serialization.Serializable

@OptIn(ExperimentalHoplite::class)
object ConfigProvider {

    val root = ConfigLoaderBuilder.default()
        .withExplicitSealedTypes()
        .addEnvironmentSource()
        .addResourceSource("/application.conf")
        .build().loadConfigOrThrow<RootConfig>()

    val authEndpointUri get() = "${requireServerConfig().baseUrl}/auth"
    val issuerEndpointUri get() = "${requireServerConfig().baseUrl}/issuer"
    val walletEndpointUri get() = "${requireServerConfig().baseUrl}/wallet"
    val verifierEndpointUri get() = "${requireServerConfig().baseUrl}/verifier"

    fun requireDatabaseConfig(): DatabaseConfig {
        return root.database ?: throw IllegalStateException("No 'database' config")
    }

    fun requireWalletConfig(): WalletConfig {
        return root.wallet ?: throw IllegalStateException("No 'wallet' config")
    }

    fun requireIssuerConfig(): IssuerConfig {
        return root.issuer ?: throw IllegalStateException("No 'issuer' config")
    }

    fun requireAuthConfig(): AuthConfig {
        return root.auth ?: throw IllegalStateException("No 'auth' config")
    }

    fun requireServerConfig(): ServerConfig {
        return root.server ?: throw IllegalStateException("No 'server' config")
    }

    fun requireServiceConfig(): ServiceConfig {
        return root.service ?: throw IllegalStateException("No 'service' config")
    }
}

@Serializable
data class RootConfig(
    val server: ServerConfig?,
    val tls: TlsConfig?,
    val issuer: IssuerConfig?,
    val wallet: WalletConfig?,
    val verifier: VerifierConfig?,
    val auth: AuthConfig?,
    val service: ServiceConfig?,
    val database: DatabaseConfig?,
)

@Serializable
data class ServerConfig(
    val host: String,
    val port: Int,
    val baseUrl: String,
)

@Serializable
data class TlsConfig(
    val enabled: Boolean,
    val keyAlias: String,
    val keystoreFile: String,
    val keystorePassword: String,
)

@Serializable
data class IssuerConfig(
    val dummy: String?
)

@Serializable
data class WalletConfig(
    val userEmail: String,
    val userPassword: String,
)

@Serializable
data class VerifierConfig(
    val dummy: String?
)

@Serializable
data class AuthConfig(
    val dummy: String?
)

@Serializable
data class ServiceConfig(
    val walletApiUrl: String,
    val issuerApiUrl: String?,
    val verifierApiUrl: String?,
    val demoWalletUrl: String,
    val devWalletUrl: String?,
)

@Serializable
data class DatabaseConfig(
    val jdbcUrl: String,
    val username: String,
    val password: String,
)

