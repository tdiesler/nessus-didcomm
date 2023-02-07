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
package org.nessus.didcomm.test

import org.junit.jupiter.api.Test
import kotlin.reflect.KClass

class TypesTest {

    @Test
    fun testTypes() {

    }
}

class TypeInfo<T: Base>(
    val baseType: KClass<T>,
    val pluginType: Plugin<T>,
    )

open class Base

class Foo: Base()

class Bar: Base()

interface Plugin<T: Base> {
    fun doStuff(obj: T)
}

class FooPlugin: Plugin<Foo> {

    override fun doStuff(obj: Foo) {
        println(obj)
    }
}

class BarPlugin: Plugin<Bar> {

    override fun doStuff(obj: Bar) {
        println(obj)
    }
}
