/*-
 * #%L
 * Nessus DIDComm :: ITests
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
package org.nessus.didcomm.itest

import io.kotest.core.spec.style.AnnotationSpec
import org.nessus.didcomm.cli.CLIService
import org.nessus.didcomm.service.ServiceMatrixLoader
import org.nessus.didcomm.util.encodeHex

val NESSUS_OPTIONS = mapOf(
    "NESSUS_USER_HOST" to System.getenv("NESSUS_USER_HOST"),
    "NESSUS_USER_PORT" to System.getenv("NESSUS_USER_PORT"),
)

object Government {
    val name = "Government"
    val seed = "000000000000000000000000Trustee1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL"
    val didkey = "did:key:z6MkukGVb3mRvTu1msArDKY9UwxeZFGjmwnCKtdQttr4Fk6i"
    val didsov = "did:sov:V4SGRU86Z58d6TV7PBUe6f"
}
object Faber {
    val name = "Faber"
    val seed = "00000000000000000000000Endorser1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "CcokUqV7WkojBLxYm7gxRzsWk3q4SE8eVMmEXoYjyvKw"
    val didkey = "did:key:z6Mkr54o55jYrJJCHqoFSgeoH6RWZd6ur7P1BNgAN5Wku97K"
    val didsov = "did:sov:NKGKtcNwssToP5f7uhsEs4"
}
object Alice {
    val name = "Alice"
    val seed = "00000000000000000000000000Alice1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "ESqH2YuYRRXMMfg5qQh1A23nzBaUvAMCEXLtBr2uDHbY"
    val didkey = "did:key:z6Mksu6Kco9yky1pUAWnWyer17bnokrLL3bYvYFp27zv8WNv"
    val didsov = "did:sov:RfoA7oboFMiFuJPEtPdvKP"
}
object Acme {
    val name = "Acme"
    val seed = "000000000000000000000000000Acme1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "4uGbbt1jJf69tjCfTiimoEtWsdCSuKndfEfFVYaw5ou4"
    val didkey = "did:key:z6MkiMXeC8GAeCad1E3N9HgceLSWhCUJKD2zMFaBKpYx12gS"
    val didsov = "did:sov:8A9VYDjAVEqWrsfjLA3VDc"
}

@Suppress("MemberVisibilityCanBePrivate")
abstract class AbstractIntegrationTest: AnnotationSpec() {

    @BeforeAll
    fun beforeAll() {
        val matrixProperties = "src/test/resources/config/service-matrix.properties"
        ServiceMatrixLoader.loadServiceDefinitions(matrixProperties)
    }

    val cliService get() = CLIService.getService()
}
