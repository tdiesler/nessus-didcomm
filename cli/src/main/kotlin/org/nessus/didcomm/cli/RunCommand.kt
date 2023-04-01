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

import id.walt.common.resolveContent
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.nio.file.Paths
import kotlin.io.path.isRegularFile

@Command(
    name = "run",
    description = ["Run commands"],
    mixinStandardHelpOptions = true
)
class RunCommand: AbstractBaseCommand() {

    companion object {
        private var callCount = 0
    }

    @Option(names = ["-h", "--headless"], description = ["Run the CLI in headless mode"])
    var headless: Boolean = false

    @Parameters(description = ["Script resource url"])
    var scriptUrl: String? = null

    override fun call(): Int {
        check(!headless || callCount == 0) { "--headless only allowed on first call" }

        val url = scriptUrl as String
        val content = when {
            url.startsWith("file:") -> {
                val path = Paths.get(url.substring(5)).toAbsolutePath()
                check(path.isRegularFile()) { "CLI script does not exist: $path"}
                resolveContent(path.toString())
            }
            else -> resolveContent(url)
        }
        check(content != url) { "Cannot find script: $url" }

        val lines = content.lines()
            .filter { it.isNotEmpty() }
            .filter { !it.startsWith("#") }
            .toMutableList()

        while (lines.isNotEmpty()) {
            val command = cliService.nextCommand(lines)
            if (command != null) {
                echo("\n>> $command")
                cliService.execute(command).onFailure {
                    return 1
                }
            }
        }

        callCount += 1

        return 0
    }
}