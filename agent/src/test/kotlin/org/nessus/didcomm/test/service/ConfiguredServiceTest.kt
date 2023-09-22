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
import id.walt.servicematrix.ServiceMatrix
import id.walt.servicematrix.ServiceProvider
import id.walt.servicematrix.ServiceRegistry
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.service.ObjectService
import org.nessus.didcomm.test.AbstractAgentTest
import java.util.concurrent.atomic.AtomicInteger

class ConfiguredServiceTest: AbstractAgentTest() {

    @Test
    fun testConcreteTestService() {
        ServiceMatrix("src/test/resources/config/service-matrix-test.properties")
        val testServiceA = ServiceRegistry.getService(SimpleTestService::class)
        testServiceA.doStuff() shouldBe "FooConfig 1"

        val testServiceB = SimpleTestService.getService()
        testServiceB.doStuff() shouldBe "FooConfig 1"

        val objectService = SimpleObjectService.getService()
        objectService.doStuff() shouldBe "FooConfig 1"
    }

    @Test
    fun testSubServiceImpl() {
        ServiceMatrix("src/test/resources/config/service-matrix-test.properties")

        // [TODO] file a bug with service matrix about double instantiation
        ServiceRegistry.getService(TestService::class).doStuff() shouldBe "FooConfig 2"
        TestService.getService().doStuff() shouldBe "FooConfig 2"
    }
}

object SimpleObjectService: ObjectService<SimpleObjectService>() {

    @JvmStatic
    fun getService() = apply { }

    private val atomicCount = AtomicInteger()
    init { atomicCount.incrementAndGet() }

    fun doStuff() = "FooConfig ${atomicCount.get()}"
}

open class SimpleTestService(private val config: String = "BarConfig") : BaseService() {
    override val implementation: SimpleTestService get() = serviceImplementation()

    companion object: ServiceProvider {
        private val atomicCount = AtomicInteger()
        override fun getService(): SimpleTestService = ServiceRegistry.getService()
    }
    init { atomicCount.incrementAndGet() }

    open fun doStuff() = "$config ${atomicCount.get()}"
}

abstract class TestService(val config: String = "BarConfig") : BaseService() {
    override val implementation: TestService get() = serviceImplementation()

    companion object: ServiceProvider {
        val atomicCount = AtomicInteger()
        override fun getService() = ServiceRegistry.getService(TestService::class)
    }
    init { atomicCount.incrementAndGet() }

    open fun doStuff(): String = implementation.doStuff()
}

class TestServiceImpl(configParam: String) : TestService(configParam) {
    override fun doStuff() = "$config ${atomicCount.get()}"
}
