package org.nessus.didcomm.cli.cmd

import picocli.CommandLine

@CommandLine.Command(name = "quit", description = ["Quit the CLI"])
class QuitCommand: AbstractBaseCommand()