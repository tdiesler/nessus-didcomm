/*-
 * #%L
 * Nessus DIDComm :: CLI
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
package org.nessus.didcomm.cli

import id.walt.common.prettyPrint
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.util.Collections

@Command(
    name = "var",
    description = ["Session variable commands"],
    mixinStandardHelpOptions = true
)
class VarCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List session variables"], mixinStandardHelpOptions = true)
    fun listVars() {
        if (properties.getVars().isNotEmpty()) {
            val maxKeyLength = Collections.max(properties.getVars().keys.mapIndexed { idx, k -> "[$idx] [$k]".length })
            sortedEntries
                .map { (k, v) -> Pair(k, v.toString()) }
                .forEachIndexed { idx, (k, v) ->
                    val valStr = if (v.length > 96) "${v.take(48)}...${v.takeLast(48)}" else v
                    echo("${"[$idx] [$k]".padEnd(maxKeyLength)} $valStr")
                }
        }
    }

    @Command(name = "show", description = ["Show a session variable"], mixinStandardHelpOptions = true)
    fun showVar(
        @Parameters(description = ["The var alias"])
        alias: String,
    ) {
        val key = alias.toIntOrNull()?.let {
            val idx = alias.toInt()
            sortedEntries[idx].key
        } ?: let {
            properties.getVars().keys.firstOrNull { it.contains(alias.lowercase()) }
        }
        key?.also { k ->
            val v = properties.getVar(k)
            echo("$k=${v?.prettyPrint()}")
        }
    }

    @Command(name = "set", description = ["Set a session variable"], mixinStandardHelpOptions = true)
    fun setVar(
        @Option(names = ["--key" ], required = true, description = ["Var key"])
        key: String,
        @Option(names = ["--val" ], required = true, description = ["Var value"])
        value: String
    ) {
        val old = properties.getVar(key)
        if (old != value) {
            properties.putVar(key, value)
            echo("Var: $key=$value")
        }
    }

    private val sortedEntries get() =
        properties.getVars().entries.sortedBy { it.key }
}