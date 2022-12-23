/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
 * %%
 * Copyright (C) 2022 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.agent.aries

import mu.KotlinLogging
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import org.apache.commons.lang3.StringUtils
import org.hyperledger.aries.config.GsonConfig
import java.util.concurrent.TimeUnit

object HttpClientFactory {

    private val log = KotlinLogging.logger {}

    fun createHttpClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .connectTimeout(60, TimeUnit.SECONDS)
            .callTimeout(60, TimeUnit.SECONDS)
            .addInterceptor(defaultLoggingInterceptor())
            .build()
    }

    fun defaultLoggingInterceptor(): HttpLoggingInterceptor {
        val gson = GsonConfig.defaultConfig()
        val pretty = GsonConfig.prettyPrinter()
        val interceptor = HttpLoggingInterceptor { msg: String ->
            if (log.isTraceEnabled && StringUtils.isNotEmpty(msg)) {
                if (msg.startsWith("{")) {
                    val json = gson.fromJson(msg, Any::class.java)
                    log.trace("\n{}", pretty.toJson(json))
                } else {
                    log.trace("{}", msg)
                }
            }
        }
        interceptor.level = HttpLoggingInterceptor.Level.BODY
        interceptor.redactHeader("Authorization")
        interceptor.redactHeader("X-API-Key")
        return interceptor
    }
}
