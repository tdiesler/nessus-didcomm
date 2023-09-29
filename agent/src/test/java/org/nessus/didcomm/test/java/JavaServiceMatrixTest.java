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
package org.nessus.didcomm.test.java;

import org.junit.jupiter.api.Test;
import org.nessus.didcomm.model.Did;
import org.nessus.didcomm.model.DidMethod;
import org.nessus.didcomm.service.DidService;
import org.nessus.didcomm.service.ServiceMatrixLoader;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

class JavaServiceMatrixTest {
    final Logger log = LoggerFactory.getLogger(JavaServiceMatrixTest.class);

    @Test
    public void testDidService() {
        String filePath = "src/test/resources/config/service-matrix.properties";
        ServiceMatrixLoader.loadServiceDefinitions(filePath);

        // The DidService on the CryptoService, which in turn loads
        // the Walt.id ContextManager via inlined Kotlin type
        // Here we test, that this actually works from plain Java

        DidService didService = DidService.getService();
        Did did = didService.createDid(DidMethod.KEY, null, null);
        log.info("{}", did);
    }
}
