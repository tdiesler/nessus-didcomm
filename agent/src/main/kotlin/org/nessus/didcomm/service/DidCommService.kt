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

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackEncryptedResult
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.PackPlaintextResult
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.PackSignedResult
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.model.UnpackResult

object DidCommService: ObjectService<DidCommService>() {

    override fun getService() = apply { }

    private val didDocResolver get() = DidDocResolverService.getService()
    private val secretResolver get() = SecretResolverService.getService()
    private val didComm get() = DIDComm(didDocResolver, secretResolver)

    fun packPlaintext(params: PackPlaintextParams): PackPlaintextResult {
        return runCatching { didComm.packPlaintext(params) }
            .onFailure { th -> log.error(th) { "Error packing: ${params.message}" } }
            .getOrThrow()
    }

    fun packSigned(params: PackSignedParams): PackSignedResult {
        return runCatching { didComm.packSigned(params) }
            .onFailure { th -> log.error(th) { "Error packing: ${params.message}" } }
            .getOrThrow()
    }

    fun packEncrypted(params: PackEncryptedParams): PackEncryptedResult {
        return runCatching { didComm.packEncrypted(params) }
            .onFailure { th -> log.error(th) { "Error packing: ${params.message}" } }
            .getOrThrow()
    }

    fun unpack(params: UnpackParams): UnpackResult {
        return runCatching { didComm.unpack(params) }
            .onFailure { th -> log.error(th) { "Error unpacking: ${params.packedMessage}" } }
            .getOrThrow()
    }
}

