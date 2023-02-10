package org.didcommx.didcomm.test.mock

import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.diddoc.DIDDocResolverInMemory
import org.didcommx.didcomm.test.diddoc.DID_DOC_ALICE_SPEC_TEST_VECTORS
import org.didcommx.didcomm.test.diddoc.DID_DOC_BOB_SPEC_TEST_VECTORS
import org.didcommx.didcomm.test.diddoc.DID_DOC_CHARLIE
import org.didcommx.didcomm.test.diddoc.DID_DOC_MEDIATOR1
import org.didcommx.didcomm.test.diddoc.DID_DOC_MEDIATOR2
import java.util.*

class DIDDocResolverMock : DIDDocResolver {
    private val didDocResolver = DIDDocResolverInMemory(
        listOf(
            DID_DOC_ALICE_SPEC_TEST_VECTORS,
            DID_DOC_BOB_SPEC_TEST_VECTORS,
            DID_DOC_CHARLIE,
            DID_DOC_MEDIATOR1,
            DID_DOC_MEDIATOR2,
        )
    )

    override fun resolve(did: String): Optional<DIDDoc> =
        didDocResolver.resolve(did)
}
