package io.nessus.identity.service

import io.kotest.matchers.string.shouldNotBeBlank
import org.junit.jupiter.api.Test

class ConfigProviderTest {

    @Test
    fun loadConfig() {

        val holder = ConfigProvider.requireHolderConfig()
        val database = ConfigProvider.requireDatabaseConfig()

        holder.walletApi.shouldNotBeBlank()
        database.jdbcUrl.shouldNotBeBlank()
    }
}