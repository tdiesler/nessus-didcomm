package org.nessus.didcomm.cli.cmd

import org.jline.terminal.Terminal
import org.jline.utils.InfoCmp
import picocli.CommandLine.Command
import java.util.concurrent.Callable

@Command(
    name = "clear",
    description = ["Clear the terminal screen"],
    mixinStandardHelpOptions = true,
)
class ClearScreenCommand(private val terminal: Terminal): Callable<Int> {

    override fun call(): Int {
        terminal.puts(InfoCmp.Capability.clear_screen, *arrayOfNulls(0))
        return 0
    }
}