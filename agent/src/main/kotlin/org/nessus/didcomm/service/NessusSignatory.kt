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

import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.W3CIssuer
import id.walt.credentials.w3c.builder.AbstractW3CCredentialBuilder
import id.walt.credentials.w3c.templates.VcTemplate
import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.services.context.ContextManager
import id.walt.services.hkvstore.HKVKey
import id.walt.signatory.ProofConfig
import id.walt.signatory.Signatory
import id.walt.signatory.SignatoryConfig
import id.walt.signatory.SignatoryDataProvider
import id.walt.signatory.WaltIdSignatory
import mu.KotlinLogging
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.io.path.absolutePathString
import kotlin.io.path.isRegularFile
import kotlin.io.path.nameWithoutExtension

class NessusSignatory(configPath: String): Signatory() {

    private val absoluteConfigPath = Paths.get(configPath).absolutePathString()
    private val delegate: Signatory = WaltIdSignatory(absoluteConfigPath)

    override val configuration: SignatoryConfig = fromConfiguration(absoluteConfigPath)

    override fun issue(
        templateIdOrFilename: String,
        config: ProofConfig,
        dataProvider: SignatoryDataProvider?,
        issuer: W3CIssuer?,
        storeCredential: Boolean
    ): String {
        return delegate.issue(templateIdOrFilename, config, dataProvider, issuer, storeCredential)
    }

    override fun issue(
        credentialBuilder: AbstractW3CCredentialBuilder<*, *>,
        config: ProofConfig,
        issuer: W3CIssuer?,
        storeCredential: Boolean
    ): String {
        return delegate.issue(credentialBuilder, config, issuer, storeCredential)
    }

    override fun listTemplates(): List<VcTemplate> {
        return CredentialTemplateManager.listTemplates(configuration.templatesFolder)
    }
    override fun listTemplateIds(): List<String> {
        return listTemplates().map { it.name }
    }

    override fun loadTemplate(templateId: String): VerifiableCredential {
        return CredentialTemplateManager.getTemplate(templateId, true, configuration.templatesFolder).template!!
    }

    override fun importTemplate(templateId: String, template: String) {
        val vc = VerifiableCredential.fromJson(template)
        CredentialTemplateManager.register(templateId, vc)
    }

    override fun removeTemplate(templateId: String) {
        val template = CredentialTemplateManager.getTemplate(templateId, true, configuration.templatesFolder)
        if (template.mutable) {
            CredentialTemplateManager.unregisterTemplate(templateId)
        } else {
            throw Exception("Template is immutable and cannot be removed. Use import to override existing templates.")
        }
    }
}

object CredentialTemplateManager {
    private val log = KotlinLogging.logger {}
    const val SAVED_VC_TEMPLATES_KEY = "vc-templates"

    fun register(name: String, template: VerifiableCredential): VcTemplate {
        template.proof = null
        template.issuer = null
        template.credentialSubject?.id = null
        template.id = null
        ContextManager.hkvStore.put(HKVKey(SAVED_VC_TEMPLATES_KEY, name), template.toJson())
        return VcTemplate(name, template, true)
    }

    fun getTemplate(
        name: String,
        loadTemplate: Boolean = true,
        runtimeTemplateFolder: String = "/vc-templates-runtime"
    ): VcTemplate {
        return ContextManager.hkvStore.getAsString(HKVKey(SAVED_VC_TEMPLATES_KEY, name))
            ?.let { VcTemplate(name, if (loadTemplate) it.toVerifiableCredential() else null, true) }
            ?: object {}.javaClass.getResource("/vc-templates/$name.json")?.readText()
                ?.let { VcTemplate(name, if (loadTemplate) it.toVerifiableCredential() else null, false) }
            ?: File("$runtimeTemplateFolder/$name.json").let {
                if (it.exists()) it.readText() else null
            }?.let { VcTemplate(name, if (loadTemplate) it.toVerifiableCredential() else null, false) }
            ?: throw IllegalArgumentException("No template found, with name $name")
    }

    private val resourceWalk = lazy {

        val resource = object {}.javaClass.getResource("/vc-templates")!!
        when {
            File(resource.file).isDirectory ->
                File(resource.file).walk().filter { it.isFile }.map { it.nameWithoutExtension }.toList()

            else -> {
                FileSystems.newFileSystem(resource.toURI(), emptyMap<String, String>()).use { fs ->
                    Files.walk(fs.getPath("/vc-templates"))
                        .filter { it.isRegularFile() }
                        .map { it.nameWithoutExtension }.toList()
                }
            }
        }
    }

    private fun listResources(): List<String> = resourceWalk.value


    private fun listRuntimeTemplates(folderPath: String): List<String> {
        val templatesFolder = File(folderPath)
        if (!templatesFolder.isDirectory) {
            log.info { "Creating templates folder: $folderPath" }
            templatesFolder.mkdirs()
        }
        return templatesFolder.walk()
            .filter { it.isFile }
            .map { it.nameWithoutExtension }
            .toList()
    }

    fun listTemplates(runtimeTemplateFolder: String = "/vc-templates-runtime"): List<VcTemplate> {
        return listResources()
            .plus(ContextManager.hkvStore.listChildKeys(HKVKey(SAVED_VC_TEMPLATES_KEY), false).map { it.name })
            .plus(listRuntimeTemplates(runtimeTemplateFolder))
            .toSet().map { getTemplate(it, false, runtimeTemplateFolder) }.toList()
    }

    fun unregisterTemplate(name: String) {
        ContextManager.hkvStore.delete(HKVKey(SAVED_VC_TEMPLATES_KEY, name))
    }
}
