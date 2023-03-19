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
import picocli.CommandLine.Parameters
import java.util.Collections.max

@Command(
    name = "variable",
    description = ["Session variable commands"],
)
class VariableCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List session variables"])
    fun listVariables() {
        val maxKeyLength = max(cliService.getVars().keys.mapIndexed { idx, k -> "[$idx] [$k]".length })
        sortedEntries.forEachIndexed { idx, (k, v) ->
            val valStr = if (v.length > 96) "${v.take(48)}...${v.takeLast(48)}" else v
            echo("${"[$idx] [$k]".padEnd(maxKeyLength)} $valStr")
        }
    }

    @Command(name = "show", description = ["Show a session variable"])
    fun showVariable(
        @Parameters(description = ["The did alias"])
        alias: String,
    ) {
        val key = alias.toIntOrNull()?.let {
            val idx = alias.toInt()
            sortedEntries[idx].key
        } ?: let {
            cliService.getVars().keys.firstOrNull { it.contains(alias.lowercase()) }
        }
        key?.also { k ->
            val v = cliService.getVar(k)
            echo("$k=${v?.prettyPrint()}")
        }
    }

    private val sortedEntries get() =
        cliService.getVars().entries.sortedBy { it.key }
}