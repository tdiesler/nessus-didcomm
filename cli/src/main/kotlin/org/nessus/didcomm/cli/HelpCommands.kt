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

import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Model.UsageMessageSpec.SECTION_KEY_COMMAND_LIST

@Command(name = "help-tree", description = ["Show tree of available commands"])
class HelpTreeCommand: AbstractBaseCommand(), Runnable {

    override fun run() {
        val cmdln = CommandLine(NessusCli())
        cmdln.helpSectionMap[SECTION_KEY_COMMAND_LIST] = CommandListRenderer()
        cmdln.usage(System.out)
    }
}

internal class CommandListRenderer : CommandLine.IHelpSectionRenderer {

    // https://github.com/remkop/picocli/blob/main/picocli-examples/src/main/java/picocli/examples/customhelp

    override fun render(help: CommandLine.Help): String {

        val spec: CommandLine.Model.CommandSpec = help.commandSpec()

        // prepare layout: two columns
        // the left column overflows, the right column wraps if text is too long
        val textTable: CommandLine.Help.TextTable = CommandLine.Help.TextTable.forColumns(
            help.colorScheme(),
            CommandLine.Help.Column(25, 2, CommandLine.Help.Column.Overflow.SPAN),
            CommandLine.Help.Column(80, 2, CommandLine.Help.Column.Overflow.SPAN)
        )
        textTable.isAdjustLineBreaksForWideCJKCharacters = spec.usageMessage().adjustLineBreaksForWideCJKCharacters()
        for (subcommand in spec.subcommands().values) {
            addHierarchy(subcommand, textTable, "")
            textTable.addRowValues("")
        }
        return textTable.toString()
    }

    private fun addHierarchy(cmd: CommandLine, textTable: CommandLine.Help.TextTable, indent: String) {
        // create comma-separated list of command name and aliases
        var names = cmd.commandSpec.names().toString()
        names = names.substring(1, names.length - 1) // remove leading '[' and trailing ']'

        // command description is taken from header or description
        val description = description(cmd.commandSpec.usageMessage())

        // add a line for this command to the layout
        textTable.addRowValues(indent + names, description)

        // add its subcommands (if any)
        for (sub in cmd.subcommands.values) {
            addHierarchy(sub, textTable, "$indent  ")
        }
    }

    private fun description(usageMessage: CommandLine.Model.UsageMessageSpec): String {
        if (usageMessage.header().isNotEmpty()) {
            return usageMessage.header()[0]
        }
        return if (usageMessage.description().isNotEmpty()) {
            usageMessage.description().get(0)
        } else ""
    }
}

