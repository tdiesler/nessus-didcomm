package org.nessus.didcomm.itest

import com.google.gson.JsonSyntaxException
import mu.KotlinLogging
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.config.GsonConfig
import org.nessus.didcomm.aries.AgentConfiguration
import java.util.concurrent.TimeUnit

abstract class AbstractAriesTest {

    val log = KotlinLogging.logger {}

    private val gson = GsonConfig.defaultConfig()

    private fun messageLoggingInterceptor(): HttpLoggingInterceptor {
        val pretty = GsonConfig.prettyPrinter()
        val logging = HttpLoggingInterceptor { msg: String ->
            if (log.isDebugEnabled && msg.isNotEmpty()) {
                if (msg.startsWith("{")) {
                    try {
                        val json: Any = gson.fromJson<Any>(msg, Any::class.java)
                        log.debug("\n{}", pretty.toJson(json))
                    } catch (e: JsonSyntaxException) {
                        log.debug("{}", msg)
                    }
                } else {
                    log.debug("{}", msg)
                }
            }
        }
        logging.level = HttpLoggingInterceptor.Level.BODY
        logging.redactHeader("X-API-Key")
        logging.redactHeader("Authorization")
        return logging
    }

    fun adminClient(loggingInterceptor: HttpLoggingInterceptor? = null): AriesClient {
        val loggingInterceptor = loggingInterceptor ?: messageLoggingInterceptor()
        val httpClient = OkHttpClient.Builder()
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .connectTimeout(60, TimeUnit.SECONDS)
            .callTimeout(60, TimeUnit.SECONDS)
            .addInterceptor(loggingInterceptor)
            .build()
        val config = AgentConfiguration.defaultConfiguration
        return AriesClient.builder()
            .url(config.adminUrl)
            .apiKey(config.apiKey)
            .client(httpClient)
            .build()
    }
}
