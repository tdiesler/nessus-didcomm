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
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.model.MessageDirection
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.Holder
import org.nessus.didcomm.util.ellipsis
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.parameterMap
import java.net.URI

object DashboardService: ObjectService<DashboardService>() {
    private val log = KotlinLogging.logger {}

    private val modelService get() = ModelService.getService()
    private val templateService get() = VcTemplateService.getService()

    override fun getService() = apply { }

    fun processHttpGet(exchange: Exchange) {
        val headers = exchange.message.headers
        when(headers["CamelHttpUri"]) {
            "/invitation" -> showInvitation(exchange)
            "/message" -> showMessage(exchange)
            "/template" -> showVcTemplate(exchange)
            "/favicon.ico" -> {}
            else -> showDashboard(exchange)
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun showDashboard(exchange: Exchange) {

        val ctx = createContext(exchange).withWalletDids()
        val httpUri = "${ctx["CamelHttpUri"]}"

        exchange.message.body = when(httpUri) {
            "/", "/dashboard"  -> showHomePage(ctx)
            "/index.css" -> showFromPath("/dashboard/index.css", ctx)
            "/dashboard/connections"  -> showConnections(httpUri, ctx)
            "/dashboard/messages"  -> showMessages(httpUri, ctx)
            else -> showFromPath(httpUri, ctx)
        }
    }

    private fun showInvitation(exchange: Exchange) {

        val ctx = createContext(exchange)

        val walletName = ctx["inviter"] as String
        val inviter = walletName.let { modelService.findWalletByName(it) }
        checkNotNull(inviter) { "No inviter for: $walletName" }

        val methodName = ctx["method"] as String
        val didMethod = methodName.let { DidMethod.fromValue(methodName) }

        val inviterDid = inviter.findDid { d -> d.method == didMethod }
        checkNotNull(inviterDid) { "Inviter has no did for: $methodName" }

        val invitation = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(inviter, inviterDid, options = mapOf(
                "goal" to "Invitation from ${inviter.name}"))
            .getMessageExchange()
            .getInvitation()

        checkNotNull(invitation) { "No invitation" }
        val invitationMessage = invitation.toMessage()

        exchange.message.headers["Content-Type"] = "application/json"
        exchange.message.body = invitationMessage.encodeJson(true)
    }

    private fun showMessage(exchange: Exchange) {

        val ctx = createContext(exchange)

        val pconId = ctx["pconId"] as String
        val epmId = ctx["epmId"] as String
        val mex = MessageExchange.findByConnectionId(pconId) as MessageExchange
        val epm = mex.messages.find { it.id == epmId } as EndpointMessage

        exchange.message.headers["Content-Type"] = "application/json"
        exchange.message.body = epm.body.encodeJson(true)
    }

    private fun showVcTemplate(exchange: Exchange) {

        val ctx = createContext(exchange)

        val templateName = ctx["name"] as String
        val vcTemplate = templateService.getTemplate(templateName)

        exchange.message.headers["Content-Type"] = "application/json"
        exchange.message.body = vcTemplate.encodeJson(true)
    }

    private fun createContext(exchange: Exchange): Context {
        val ctx = Context(exchange)
        val httpQuery = "${ctx["CamelHttpQuery"]}"
        if (httpQuery.isNotEmpty()) {
            val httpUrl = "${ctx["CamelHttpUrl"]}"
            val fullUri = URI("$httpUrl?$httpQuery")
            ctx.putAll(fullUri.parameterMap())
        }
        if (ctx["method"] == null)
            ctx["method"] = "key"
        return ctx
    }

    private fun fromTemplate(path: String, ctx: Map<String, Any> = mapOf()): String {
        val content = resolveContent(path)
        check(content != path) { "No content for: $path" }
        val contentHolder = Holder(content)
        ctx.forEach { (k, v) ->
            val input = contentHolder.value as String
            contentHolder.value = input.replace("\${$k}", "$v")
        }
        return contentHolder.value as String
    }

    private fun showFromPath(path: String, ctx: Context): String {
        val (resourcePath, contentType) = when {
            path.endsWith(".css") -> Pair("class:$path", "text/css")
            path.endsWith(".html") -> Pair("class:$path", "text/html")
            path.endsWith(".json") -> Pair("class:$path", "application/json")
            else -> Pair("class:${path}.html", "text/html")
        }
        val content = resolveContent(resourcePath)
        check(content != resourcePath) { "No content for: $resourcePath" }
        val contentHolder = Holder(content)
        ctx.forEach { (k, v) ->
            val input = contentHolder.value as String
            contentHolder.value = input.replace("\${$k}", "$v")
        }
        ctx.exchange.message.headers["Content-Type"] = contentType
        return contentHolder.value as String
    }

    private fun showHomePage(ctx: Context): String {
        return fromTemplate("class:dashboard/index.html",
            ctx.withVcTemplates())
    }

    private fun showConnections(path: String, ctx: Context): String {

        val walletName = ctx["walletName"] as String
        val wallet = modelService.findWalletByName(walletName) as Wallet
        if (wallet.connections.isEmpty()) {
            ctx["walletConnectionRows"] = "None"
            return showFromPath(path, ctx)
        }
        val walletConnectionRows = wallet.connections
            .mapIndexed { idx, con -> Pair(idx, con) }
            .filter { (_, con) -> con.state == ConnectionState.ACTIVE }
            .joinToString(separator = "\n") { (idx, con) ->
                """
                <tr>
                    <td class='code'>${idx}</td>
                    <td class='code'><a href='/dashboard/messages?walletName=${walletName}&pconId=${con.id}'>${con.alias}</a></td>
                    <td class='code'>${con.theirDid.uri.ellipsis(24)}</td>
                    <td class='code'>${con.theirEndpointUrl}</td>
                </tr>
                """.trimIndent()
        }
        ctx["walletConnectionRows"] = walletConnectionRows
        return showFromPath(path, ctx)
    }

    private fun showMessages(path: String, ctx: Context): String {

        val walletName = ctx["walletName"] as String
        val connectionId = ctx["pconId"] as String
        val wallet = modelService.findWalletByName(walletName) as Wallet

        val pcon = wallet.getConnection(connectionId)
        val mex = MessageExchange.findByConnectionId(pcon.id)
        val messages = mex?.messages
        if (messages.isNullOrEmpty()) {
            ctx["pconAlias"] = pcon.alias
            return showFromPath(path, ctx)
        }

        val idxAndDirection = { i: Int, m: EndpointMessage -> when(m.messageDirection) {
            MessageDirection.IN -> "[$i] <<"
            MessageDirection.OUT -> "[$i] >>"
            else -> "[$i] .."
        }}

        val epmRows = messages
            .mapIndexed { idx, epm -> Pair(idx, epm) }
            .joinToString(separator = "\n") { (idx, epm) ->
                """
                <tr>
                    <td class='code'>${idxAndDirection(idx, epm)}</td><td class='code'>${epm.shortString()}</td>
                    <td><a href='/message?pconId=${pcon.id}&epmId=${epm.id}'>show</a></td>
                </tr>
                """.trimIndent()
            }
        ctx["pconAlias"] = pcon.alias
        ctx["epmRows"] = epmRows
        return showFromPath(path, ctx)
    }

    class Context(val exchange: Exchange): LinkedHashMap<String, Any>(exchange.message.headers) {

        private val modelService get() = ModelService.getService()
        private val templateService get() = VcTemplateService.getService()

        init {
            val buildNumber = resolveContent("class:buildNumber.txt")
            val nessusVersion = resolveContent("class:version.txt")
            put("buildNumber", buildNumber)
            put("nessusVersion", nessusVersion)
            put("method", "key")
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
                .filter { w -> w.dids.any { d -> d.method == DidMethod.fromValue(method) } }
                .map { w -> Pair(w, w.dids.first { d -> d.method == DidMethod.fromValue(method) }) }
                .joinToString(separator = "\n") { (w, d) ->
                    put("${w.name}.Did", d.uri)
                    """
                    <tr>
                        <td><b>${w.name}</b></td><td class='code'>${d.uri.ellipsis(24)}</td>
                        <td><a href='/invitation?inviter=${w.name}&method=$method'>invitation</a></td>
                        <td><a href='/dashboard/connections?walletName=${w.name}'>connections</a></td>
                    </tr>
                    """
                }

            put("walletDids", walletDids)
        }
    }
}
