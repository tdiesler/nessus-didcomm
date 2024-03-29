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
package org.nessus.didcomm.test.java;

import com.google.gson.Gson;
import id.walt.signatory.revocation.RevocationResult;
import org.junit.jupiter.api.Test;
import org.nessus.didcomm.util.EncodingKt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

class JavaSerializationTest {
    final Logger log = LoggerFactory.getLogger(JavaSerializationTest.class);

    @Test
    public void testRevocationResult() {

        RevocationResult exp = new RevocationResult(true, "foo");
        String json = EncodingKt.encodeJson(exp, false);
        log.info(json);

        Gson gson = EncodingKt.getGson();
        RevocationResult was = gson.fromJson(json, RevocationResult.class);
        log.info("{}", was);

        Map<String, Object> map = EncodingKt.decodeJson(json);
        was = gson.fromJson(gson.toJson(map), RevocationResult.class);
        log.info("{}", was);
    }
}
