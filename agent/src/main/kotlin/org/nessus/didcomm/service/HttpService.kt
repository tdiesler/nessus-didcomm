/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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
package org.nessus.didcomm.service

import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.logging.HttpLoggingInterceptor
import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_MEDIA_TYPE
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_TYPE
import org.nessus.didcomm.service.HttpService.HttpClient.Companion.createHttpLoggingInterceptor
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.slf4j.event.Level
import java.util.concurrent.TimeUnit


class HttpService: NessusBaseService() {
    override val implementation get() = serviceImplementation<HttpService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        val DEFAULT_HTTP_LOGGING_LEVEL = Level.INFO
        private val implementation = HttpService()
        override fun getService() = implementation
    }

    fun httpClient(level: Level? = null): HttpClient {
        return HttpClient(createHttpLoggingInterceptor(level), null)
    }

    fun httpClient(loggingInterceptor: HttpLoggingInterceptor?, httpClient: OkHttpClient?): HttpClient {
        return HttpClient(loggingInterceptor, httpClient)
    }

    class HttpClient(loggingInterceptor: HttpLoggingInterceptor? = null, httpClient: OkHttpClient? = null) {
        val log = KotlinLogging.logger {}

        private val httpClient: OkHttpClient
        init {
            this.httpClient = httpClient ?: OkHttpClient.Builder()
                .writeTimeout(60, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .connectTimeout(60, TimeUnit.SECONDS)
                .callTimeout(60, TimeUnit.SECONDS)
                .addInterceptor(loggingInterceptor ?: createHttpLoggingInterceptor())
                .build()
        }

        companion object {
            fun createHttpLoggingInterceptor(level: Level? = null): HttpLoggingInterceptor {
                val effLevel = level ?: DEFAULT_HTTP_LOGGING_LEVEL
                val log = KotlinLogging.logger {}
                fun log(spec: String, msg: String) {
                    when(effLevel) {
                        Level.ERROR -> log.error(spec, msg)
                        Level.WARN -> log.warn(spec, msg)
                        Level.INFO -> log.info(spec, msg)
                        Level.DEBUG -> log.debug(spec, msg)
                        else -> log.trace(spec, msg)
                    }
                }
                val interceptor = HttpLoggingInterceptor { msg: String ->
                    if (log.isEnabledForLevel(effLevel) && msg.isNotEmpty()) {
                        if (msg.startsWith("{")) {
                            val json = msg.decodeJson()
                            log("{}", json.encodeJson(true))
                        } else {
                            log("{}", msg)
                        }
                    }
                }
                interceptor.level = HttpLoggingInterceptor.Level.BODY
                interceptor.redactHeader("X-API-Key")
                interceptor.redactHeader("Authorization")
                return interceptor
            }
        }

        fun post(reqUrl: String, body: Any, params: Map<String, Any>? = null, headers: Map<String, String> = mapOf()): Response {

            // Build the Request
            var actUrl = reqUrl
            if (params != null) {
                actUrl += "?"
                params.forEach { (k, v) -> actUrl += "$k=$v&"}
                actUrl = actUrl.dropLast(1)
            }
            val builder = Request.Builder().url(actUrl)

            headers.filterKeys { it !in listOf("Content-Type", MESSAGE_HEADER_MEDIA_TYPE) }
                .forEach { (k, v) -> builder.header(k, v) }

            // The given Content-Type or JSON by default
            var contentType = headers["Content-Type"] ?: headers[MESSAGE_HEADER_MEDIA_TYPE]
            if (contentType == null && headers[MESSAGE_HEADER_TYPE]?.startsWith("application/") == true) {
                contentType = headers[MESSAGE_HEADER_TYPE]
            }

            val mediaType = contentType?.toMediaType() ?: "application/json".toMediaType()

            val reqBody = when (body) {
                is String -> body.toRequestBody(mediaType)
                is ByteArray -> body.toRequestBody(mediaType)
                is Message -> body.encodeJson().toRequestBody(mediaType)
                else -> throw IllegalArgumentException("Unsupported body type: ${body.javaClass}")
            }

            val req = builder.post(reqBody).build()
            val res = httpClient.newCall(req).execute()
            log.debug { "code=${res.code} message=${res.message}" }
            return res
        }
    }
}
