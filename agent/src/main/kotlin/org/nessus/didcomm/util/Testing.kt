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
package org.nessus.didcomm.util

import io.kotest.core.annotation.EnabledCondition
import io.kotest.core.spec.Spec
import org.nessus.didcomm.model.Invitation
import java.net.URL
import kotlin.reflect.KClass


class NessusIsLiveCondition : EnabledCondition {
    override fun enabled(kclass: KClass<out Spec>): Boolean {
        // [TODO] Add a liveness/readiness endpoint to the playground
        val url = "http://localhost:9100/message/invitation?inviter=Government&method=key"
        return runCatching { Invitation.fromUrl(URL(url)) }
            .onFailure { /* ignore*/ }
            .isSuccess
    }
}
