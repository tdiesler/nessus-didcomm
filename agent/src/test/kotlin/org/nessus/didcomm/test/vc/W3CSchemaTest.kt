/*-
 * #%L
 * Nessus DIDComm :: Core
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
package org.nessus.didcomm.test.vc

import id.walt.credentials.w3c.W3CCredentialSchema
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.w3c.W3CCredentialSchemaBuilder
import org.nessus.didcomm.w3c.W3CCredentialSchemaBuilder.SchemaBuilder
import java.time.OffsetDateTime

class W3CSchemaTest: AbstractAgentTest() {

    @Test
    fun parseSimpleEmailSchema() {
        val exp = readResource("/w3c/schemas/email-schema.json")
        val schema1 = W3CCredentialSchema.fromJson(exp)
        schema1.id shouldBe "did:example:MDP8AsFhHzhwUvGNuYkX7T/06e126d1-fa44-4882-a243-1e326fbe21db?version=1.0"

        val schema2 = W3CCredentialSchemaBuilder(
            id = "did:example:MDP8AsFhHzhwUvGNuYkX7T/06e126d1-fa44-4882-a243-1e326fbe21db?version=1.0",
            name = "Email",
            version = "1.0",
            author = "did:example:MDP8AsFhHzhwUvGNuYkX7T",
            schema = """
            {
                "${'$'}id": "email-schema-1.0",
                "${'$'}schema": "https://json-schema.org/draft/2019-09/schema",
                "description": "Email",
                "type": "object",
                "properties": {
                  "emailAddress": {
                    "type": "string",
                    "format": "email"
                  }
                },
                "required": ["emailAddress"],
                "additionalProperties": false
            }                
            """.trimJson())
            .type("https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json")
            .authored(OffsetDateTime.parse("2022-05-05T00:00:00+00:00"))
            .build()

        schema2.id shouldBe schema1.id
        schema2.type shouldBe schema1.type
        schema2.properties shouldBe schema1.properties

        val schema3 = W3CCredentialSchemaBuilder(
            id = "did:example:MDP8AsFhHzhwUvGNuYkX7T/06e126d1-fa44-4882-a243-1e326fbe21db?version=1.0",
            name = "Email",
            version = "1.0",
            author = "did:example:MDP8AsFhHzhwUvGNuYkX7T",
            schema = SchemaBuilder("email-schema-1.0")
                .schema("https://json-schema.org/draft/2019-09/schema")
                .description("Email")
                .property("emailAddress", "string", format = "email")
                .build())
            .type("https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json")
            .authored(OffsetDateTime.parse("2022-05-05T00:00:00+00:00"))
            .build()

        schema3.id shouldBe schema1.id
        schema3.type shouldBe schema1.type
        schema3.properties shouldBe schema1.properties
    }
}

