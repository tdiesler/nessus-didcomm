package org.nessus.didcomm.cli.cmd

import picocli.CommandLine.Option

open class DidCommV2Command: AbstractBaseCommand() {

    @Option(names = ["--sign" ], description = ["Sign the DIDComm V2 messages"])
    var sign: Boolean = false

    @Option(names = ["--encrypt" ], description = ["Encrypt the DIDComm V2 messages"])
    var encrypt: Boolean = false
}