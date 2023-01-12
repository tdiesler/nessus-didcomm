package org.nessus.didcomm.service

import id.walt.servicematrix.BaseService
import mu.KotlinLogging

abstract class NessusBaseService: BaseService() {
    val log = KotlinLogging.logger {}
}