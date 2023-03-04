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

import org.didcommx.didcomm.diddoc.DIDDocDecoder
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.message.Attachment
import org.nessus.didcomm.did.DidDocV2
import org.nessus.didcomm.did.SicpaDidDoc
import org.nessus.didcomm.did.toSicpaDidDoc
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import java.util.Optional
import java.util.UUID

/**
 * https://w3c.github.io/did-core/#iana-considerations
 */
const val DID_DOCUMENT_MEDIA_TYPE = "application/did+json"

object DidDocumentV2Service: ObjectService<DidDocumentV2Service>(), DIDDocResolver {

    override fun getService() = apply { }

    private val didService get() = DidService.getService()

    override fun resolve(did: String): Optional<SicpaDidDoc> {
        val didDoc = resolveDidDocument(did).toSicpaDidDoc()
        return Optional.ofNullable(didDoc)
    }

    fun resolveDidDocument(did: String): DidDocV2 {
        return didService.loadDidDocument(did)
    }

    fun createDidDocAttachment(didDoc: DidDocV2): Attachment {
        val didDocMap = didDoc.encodeJson().decodeJson()
        val jsonData = Attachment.Data.Json.parse(mapOf("json" to didDocMap))
        return Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .mediaType(DID_DOCUMENT_MEDIA_TYPE)
            .build()
    }

    fun extractDidDocAttachment(attachment: Attachment): DidDocV2 {
        require(attachment.mediaType == DID_DOCUMENT_MEDIA_TYPE) { "Unexpected media_type: ${attachment.mediaType} "}

        val didDocAttachment = gson.toJson(attachment.data.toJSONObject()["json"])
        checkNotNull(didDocAttachment) {"Cannot find attached did document"}
        return DidDocV2.fromSicpaDidDoc(DIDDocDecoder.decodeJson(didDocAttachment))
    }
}

