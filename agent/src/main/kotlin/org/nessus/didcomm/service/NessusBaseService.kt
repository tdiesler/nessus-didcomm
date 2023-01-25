package org.nessus.didcomm.service

import id.walt.servicematrix.BaseService
import mu.KLogger
import mu.KotlinLogging

abstract class NessusBaseService: BaseService() {
    abstract val log: KLogger
}