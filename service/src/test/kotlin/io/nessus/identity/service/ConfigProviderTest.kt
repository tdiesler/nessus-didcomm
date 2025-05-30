package io.nessus.identity.service

import io.kotest.matchers.string.shouldNotBeBlank
import org.junit.jupiter.api.Test

class ConfigProviderTest {

    @Test
    fun loadConfig() {

        val holder = ConfigProvider.requireHolderConfig()
        val service = ConfigProvider.requireServiceConfig()
        val database = ConfigProvider.requireDatabaseConfig()

        holder.userEmail.shouldNotBeBlank()
        holder.userPassword.shouldNotBeBlank()

        service.demoWalletUrl.shouldNotBeBlank()

        database.jdbcUrl.shouldNotBeBlank()
    }
}