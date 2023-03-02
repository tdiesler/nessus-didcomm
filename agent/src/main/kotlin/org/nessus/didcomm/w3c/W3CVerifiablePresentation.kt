package org.nessus.didcomm.w3c

import org.nessus.didcomm.util.decodeJson

typealias WaltIdVerifiablePresentation = id.walt.credentials.w3c.VerifiablePresentation

class W3CVerifiablePresentation private constructor(jsonObject: Map<String, Any>) : W3CVerifiableCredential(jsonObject) {

    companion object {
        fun fromJson(input: String) = run {
            W3CVerifiablePresentation(input.decodeJson())
        }
    }
}