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

import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.nessus.didcomm.model.SicpaDidDoc
import java.util.Optional

object DidDocResolverService: ObjectService<DidDocResolverService>(), DIDDocResolver {

    @JvmStatic
    fun getService() = apply { }

    private val didService get() = DidService.getService()

    override fun resolve(did: String): Optional<SicpaDidDoc> {
        val didDoc = didService.loadOrResolveDidDoc(did)
        checkNotNull(didDoc) { "Cannot resolve did: $did" }
        return Optional.ofNullable(didDoc.toSicpaDidDoc())
    }
}

