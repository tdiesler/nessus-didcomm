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
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.message.Attachment
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidDocV2
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import java.util.Optional
import java.util.UUID
import kotlin.jvm.optionals.getOrNull

/**
 * https://w3c.github.io/did-core/#iana-considerations
 */
const val DID_DOCUMENT_MEDIA_TYPE = "application/did+json"


@OptIn(ExperimentalStdlibApi::class)
class DidDocumentV2Service: NessusBaseService(), DIDDocResolver {
    override val implementation get() = serviceImplementation<DidService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = DidDocumentV2Service()
        override fun getService() = implementation
    }

    private val documentStore = mutableMapOf<String, DidDocV2>()

    fun createDidDocument(did: Did, endpointUrl: String): DidDocV2 {
        check(!documentStore.containsKey(did.qualified)) { "Document for ${did.qualified} already registered" }
        val didDoc = DidDocV2.Builder(did.qualified)
            .didCommService(endpointUrl)
            .authentication()
            .keyAgreement()
            .build()
        addDidDocument(didDoc)
        return didDoc
    }

    fun addDidDocument(didDoc: DidDocV2) {
        check(!documentStore.containsKey(didDoc.did)) { "Document for ${didDoc.did} already registered" }
        documentStore[didDoc.did] = didDoc
    }

    fun removeDidDocument(didDoc: DidDocV2): DidDocV2? {
        return documentStore.remove(didDoc.did)
    }

    override fun resolve(did: String): Optional<DIDDoc> {
        val didDoc = documentStore[did]?.run { toDIDDoc() }
        return Optional.ofNullable(didDoc)
    }

    fun resolveDidDocument(did: String): DidDocV2 {
        val didDoc = resolve(did).getOrNull()
        checkNotNull(didDoc) { "No Did Document for: $did" }
        return DidDocV2.fromDIDDoc(didDoc)
    }

    fun createDidDocAttachment(didDoc: DidDocV2): Attachment {
        val didDocAttachMap = didDoc.encodeJson().decodeJson()
        val jsonData = Attachment.Data.Json.parse(mapOf("json" to didDocAttachMap))
        return Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .mediaType(DID_DOCUMENT_MEDIA_TYPE)
            .build()
    }

    fun extractDidDocAttachment(attachment: Attachment): DidDocV2 {
        require(attachment.mediaType == DID_DOCUMENT_MEDIA_TYPE) { "Unexpected media_type: ${attachment.mediaType} "}

        val didDocAttachment = gson.toJson(attachment.data.toJSONObject()["json"])
        checkNotNull(didDocAttachment) {"Cannot find attached did document"}

        return gson.fromJson(didDocAttachment, DidDocV2::class.java)
    }
}

