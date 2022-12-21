package org.nessus.didcomm.agent.aries

import com.google.gson.JsonObject
import mu.KotlinLogging
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.apache.commons.lang3.StringUtils
import org.hyperledger.acy_py.generated.model.DID
import org.hyperledger.aries.api.exception.AriesException
import org.hyperledger.aries.api.ledger.IndyLedgerRoles
import org.hyperledger.aries.config.GsonConfig
import java.util.concurrent.TimeUnit

class SelfRegistrationHandler(private val networkURL: String) {

    private val log = KotlinLogging.logger {}
    private val gson = GsonConfig.defaultConfig()

    companion object {
        private val httpClient = OkHttpClient.Builder()
            .writeTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .connectTimeout(60, TimeUnit.SECONDS)
            .callTimeout(60, TimeUnit.SECONDS)
            .build()
    }

    fun registerWithDID(alias: String?, did: String?, verkey: String?, role: IndyLedgerRoles?): Boolean {
        var json = JsonObject()
        json.addProperty("did", did)
        json.addProperty("verkey", verkey)
        if (alias != null) json.addProperty("alias", alias)
        if (role != null) json.addProperty("role", role.toString())
        log.info("Self register: {}", json)
        val res = call(buildPost(json))
        json = gson.fromJson(res, JsonObject::class.java)
        log.info("Respose: {}", json)
        return true
    }

    fun registerWithSeed(alias: String?, seed: String?, role: IndyLedgerRoles?): DID {
        val json = JsonObject()
        json.addProperty("seed", seed)
        if (alias != null) json.addProperty("alias", alias)
        if (role != null) json.addProperty("role", role.toString())
        log.info("Self register: {}", json)
        val res = call(buildPost(json))
        val did = gson.fromJson(res, DID::class.java)
        log.info("Respose: {}", did)
        return did
    }

    private fun buildPost(body: Any): Request {
        val jsonType: MediaType = "application/json; charset=utf-8".toMediaType()
        val jsonBody: RequestBody = gson.toJson(body).toRequestBody(jsonType)
        return Request.Builder().url(networkURL).post(jsonBody).build()
    }

    private fun call(req: Request): String? {
        var result: String? = null
        httpClient.newCall(req).execute().use { resp ->
            if (resp.isSuccessful && resp.body != null) {
                result = resp.body!!.string()
            } else if (!resp.isSuccessful) {
                handleError(resp)
            }
        }
        return result
    }

    private fun handleError(resp: Response) {
        val msg = if (StringUtils.isNotEmpty(resp.message)) resp.message else ""
        val body = if (resp.body != null) resp.body!!.string() else ""
        log.error("code={} message={}\nbody={}", resp.code, msg, body)
        throw AriesException(resp.code, """
             $msg
             $body
             """.trimIndent()
        )
    }
}
