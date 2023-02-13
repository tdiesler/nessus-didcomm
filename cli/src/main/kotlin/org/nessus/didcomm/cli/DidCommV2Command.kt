package org.nessus.didcomm.cli

import picocli.CommandLine.Option

open class DidCommV2Command: AbstractBaseCommand() {

    @Option(names = ["--dcv2" ], description = ["Use DIDComm V2 messages"])
    var dcv2: Boolean = false
}