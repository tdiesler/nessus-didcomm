package io.nessus.identity.proxy

import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.OpenID4VCIVersion
import io.nessus.identity.service.ConfigProvider.config

object NessusOpenID4VCI {

    val issuerMetadataUrl = OpenID4VCI.getCIProviderMetadataUrl(config.baseUrl)
    val issuerMetadata = OpenID4VCI.createDefaultProviderMetadata(config.baseUrl, emptyMap(), OpenID4VCIVersion.DRAFT13)

}

