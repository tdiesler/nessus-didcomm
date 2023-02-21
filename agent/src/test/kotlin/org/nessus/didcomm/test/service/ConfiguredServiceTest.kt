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
package org.nessus.didcomm.test.service

import id.walt.servicematrix.BaseService
import id.walt.servicematrix.ServiceProvider
import id.walt.servicematrix.ServiceRegistry
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.test.AbstractAgentTest

class ConfiguredServiceTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun testConcreteTestService() {
        ServiceRegistry.registerService<ConcreteTestService>(ConcreteTestService("FooConfig"))
        val testService = ServiceRegistry.getService(ConcreteTestService::class)
        testService.doStuff() shouldBe "FooConfig"
    }

    @Test
    fun testSubServiceImpl() {
        ServiceRegistry.registerService<TestService>(TestServiceImpl("FooConfig"))
        val testService: TestService = ServiceRegistry.getService()
        testService.doStuff() shouldBe "FooConfig"
    }
}

open class ConcreteTestService(val config: String = "BarConfig") : BaseService() {
    override val implementation: ConcreteTestService get() = serviceImplementation()

    open fun doStuff(): String = config

    companion object : ServiceProvider {
        override fun getService() = object : ConcreteTestService() {}
    }
}

abstract class TestService(val config: String = "BarConfig") : BaseService() {
    override val implementation: TestService get() = serviceImplementation()

    open fun doStuff(): String = implementation.doStuff()

    companion object : ServiceProvider {
        override fun getService() = object : TestService() {}
    }
}

class TestServiceImpl(configParam: String) : TestService(configParam) {
    override fun doStuff() = config
}
