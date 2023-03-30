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

import id.walt.common.resolveContent
import id.walt.credentials.w3c.templates.VcTemplateService
import mu.KotlinLogging
import org.apache.camel.Exchange
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.util.Holder
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.parameterMap
import java.net.URI

object PlaygroundService: ObjectService<PlaygroundService>() {
    private val log = KotlinLogging.logger {}

    private val modelService get() = ModelService.getService()
    private val templateService get() = VcTemplateService.getService()

    override fun getService() = apply { }

    fun showDashboard(exchange: Exchange) {

        val context = createContext(exchange).withWalletDids()
        val httpUri = "${context["CamelHttpUri"]}"

        exchange.message.headers["Content-Type"] = "text/html"
        exchange.message.body = when(httpUri) {
            "/", "/playground"  -> showHomePage(context)
            "/index.css" -> fromTemplate("class:playground/index.css")
            else -> showFromPath(httpUri, context)
        }
    }

    fun showInvitation(exchange: Exchange) {

        val context = createContext(exchange)

        val walletName = context["inviter"] as String
        val inviter = walletName.let { modelService.findWalletByName(it) }
        checkNotNull(inviter) { "No inviter for: $walletName" }

        val methodName = context["method"] as String
        val didMethod = methodName.let { DidMethod.fromValue(methodName) }

        val inviterDid = inviter.findDid { d -> d.method == didMethod }
        checkNotNull(inviterDid) { "Inviter has no did for: $methodName" }

        val invitation = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(inviter, inviterDid, mapOf(
                "goal_code" to "issue-vc",
                "goal" to "Invitation from ${inviter.name}"))
            .getMessageExchange()
            .getInvitation()

        checkNotNull(invitation) { "No invitation" }
        val invitationMessage = invitation.actV2.toMessage()

        exchange.message.headers["Content-Type"] = "application/json"
        exchange.message.body = invitationMessage.encodeJson(true)
    }

    fun showVcTemplate(exchange: Exchange) {

        val context = createContext(exchange)

        val templateName = context["name"] as String
        val vcTemplate = templateService.getTemplate(templateName)

        exchange.message.headers["Content-Type"] = "application/json"
        exchange.message.body = vcTemplate.encodeJson(true)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createContext(exchange: Exchange): Context {
        val context = Context(exchange.message.headers)
        val httpQuery = "${context["CamelHttpQuery"]}"
        if (httpQuery.isNotEmpty()) {
            val httpUrl = "${context["CamelHttpUrl"]}"
            val fullUri = URI("$httpUrl?$httpQuery")
            context.putAll(fullUri.parameterMap())
        }
        if (context["method"] == null)
            context["method"] = "key"
        return context
    }

    private fun fromTemplate(path: String, context: Map<String, Any> = mapOf()): String {
        val content = resolveContent(path)
        check(content != path) { "No content for: $path" }
        val contentHolder = Holder(content)
        context.forEach { (k, v) ->
            val input = contentHolder.value as String
            contentHolder.value = input.replace("\${$k}", "$v")
        }
        return contentHolder.value as String
    }

    private fun showFromPath(path: String, context: Context): String {
        val content = resolveContent("class:${path}.html")
        check(content != path) { "No content for: $path" }
        val contentHolder = Holder(content)
        context.forEach { (k, v) ->
            val input = contentHolder.value as String
            contentHolder.value = input.replace("\${$k}", "$v")
        }
        return contentHolder.value as String
    }

    private fun showHomePage(context: Context): String {
        return fromTemplate("class:playground/index.html",
            context.withVcTemplates())
    }
}

class Context(init: Map<String, Any>): LinkedHashMap<String, Any>(init) {

    private val modelService get() = ModelService.getService()
    private val templateService get() = VcTemplateService.getService()

    init {
        val buildNumber = resolveContent("class:buildNumber.txt")
        val nessusVersion = resolveContent("class:version.txt")
        put("buildNumber", buildNumber)
        put("nessusVersion", nessusVersion)
    }

    fun withVcTemplates() = apply {
        val vcTemplates = templateService.listTemplates().sortedBy { it.name }
            .joinToString(separator = "\n") { t ->
                "<li><a href='/template?name=${t.name}'>${t.name}</a>"
            }
        put("vcTemplates", vcTemplates)
    }

    fun withWalletDids() = apply {
        val method = get("method") as String
        val walletDids = modelService.wallets
            .filter { w -> w.dids.isNotEmpty() }
            .map { w -> Pair(w, w.dids.find { d -> d.method == DidMethod.fromValue(method) }) }
            .joinToString(separator = "\n") { (w, d) ->
                put("${w.name}.Did", d!!.uri)
                "<tr><td><b>${w.name}</b></td><td class='code'>${d.uri}</td><td><a href='/message/invitation?inviter=${w.name}&method=$method'>invitation</a></td></tr>"
            }

        put("walletDids", walletDids)
    }
}