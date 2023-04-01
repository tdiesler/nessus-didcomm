package org.nessus.didcomm.itest

import mu.KotlinLogging
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.util.Holder
import org.nessus.didcomm.util.decodeJson


/**
 * Verifiable Credentials
 * ----------------------
 *
 * Malathi's passport
 *      Establishes identity of the traveling parent
 *
 * Anand's passport
 *      Establishes identity of the minor
 *
 * Anand's Birth Certificate
 *      Establishes relationship to parents and provides link from Rajesh to Anand that qualifies the permission to travel
 *
 * Permission to travel from Rajesh
 *      Grants permission from non-traveling parent for minor to travel
 *
 * https://www.w3.org/TR/vc-use-cases/#international-travel-with-minor-and-upgrade
 */
class TravelWithMinorIntegrationTest<T: AutoCloseable>: AbstractIntegrationTest() {
    private val log = KotlinLogging.logger {}

    data class Context(
        val government: Wallet,
        val hospital: Wallet,
        val airport: Wallet,
        val malathi: Wallet,
        val rajesh: Wallet,
        val anand: Wallet,
    ) {
        var malathiGov: Connection? = null
        var malathiHos: Connection? = null
        var malathiAir: Connection? = null
        var malathiRaj: Connection? = null
        var rajeshGov: Connection? = null
        var anandDid: Did? = null

        var issuerDid: Did? = null
        var holderDid: Did? = null
        var verifierDid: Did? = null
    }

    private val contextHolder = Holder<Context>()

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint(NESSUS_OPTIONS)
        contextHolder.value = Context(
            government = Wallet.Builder("Government").build(),
            hospital = Wallet.Builder("Hospital").build(),
            airport = Wallet.Builder("Airport").build(),
            malathi = Wallet.Builder("Malathi").build(),
            rajesh = Wallet.Builder("Rajesh").build(),
            anand = Wallet.Builder("Anand").build(),
        )
    }

    @AfterAll
    fun stopAgent() {
        val ctx = contextHolder.value!!
        removeWallet(ctx.government)
        removeWallet(ctx.hospital)
        removeWallet(ctx.airport)
        removeWallet(ctx.malathi)
        removeWallet(ctx.rajesh)
        removeWallet(ctx.anand)
        stopNessusEndpoint<T>()
    }

    @Test
    fun travelWithMinor() {

        val ctx = contextHolder.value!!

        // Malathi Passport ============================================================================================

        MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(ctx.government)
            .receiveOutOfBandInvitation(ctx.malathi)

            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                ctx.malathiGov = pcon
                ctx.issuerDid = pcon.theirDid
                ctx.holderDid = pcon.myDid
            }

            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                issuerDid = ctx.issuerDid!!,
                holder = ctx.malathi,
                template = "Passport",
                subjectData = """{
                    "givenName": "Malathi",
                    "familyName": "Hamal",
                    "citizenship": "US"
                }""".decodeJson())
            .awaitCredentialOffer(ctx.malathi, ctx.issuerDid!!)
            .awaitIssuedCredential(ctx.malathi, ctx.issuerDid!!)

        // Rajesh Passport =============================================================================================

        MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(ctx.government)
            .receiveOutOfBandInvitation(ctx.rajesh)

            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                ctx.rajeshGov = pcon
                ctx.issuerDid = pcon.theirDid
                ctx.holderDid = pcon.myDid
            }

            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                issuerDid = ctx.issuerDid!!,
                holder = ctx.rajesh,
                template = "Passport",
                subjectData = """{
                    "givenName": "Rajesh",
                    "familyName": "Hamal",
                    "citizenship": "US"
                }""".decodeJson())
            .awaitCredentialOffer(ctx.rajesh, ctx.issuerDid!!)
            .awaitIssuedCredential(ctx.rajesh, ctx.issuerDid!!)

        // Malathi BirthCertificate ====================================================================================

        MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(ctx.hospital)
            .receiveOutOfBandInvitation(ctx.malathi)

            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                ctx.malathiHos = pcon
                ctx.issuerDid = pcon.theirDid
                ctx.holderDid = pcon.myDid
                ctx.anandDid = ctx.anand.createDid(DidMethod.KEY)
            }

            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                issuerDid = ctx.issuerDid!!,
                holder = ctx.malathi,
                template = "BirthCertificate",
                subjectData = """{
                    "id": "${ctx.anandDid!!.uri}",
                    "givenName": "Anand",
                    "familyName": "Hamal",
                    "birthDate": "2022-03-29T00:00:00Z",
                    "birthPlace": {
                       "type": "Hospital",
                       "address": {
                           "type": "US address",
                           "addressLocality": "Denver",
                           "addressRegion": "CO",
                           "postalCode": "80209",
                           "streetAddress": "123 Main St."
                       }
                    },
                    "citizenship": "US",
                    "parent": [
                       {
                         "id": "${ctx.malathiGov!!.myDid.uri}",
                         "givenName": "Malathi",
                         "familyName": "Hamal"
                       },
                       {
                         "id": "${ctx.rajeshGov!!.myDid.uri}",
                         "givenName": "Rajesh",
                         "familyName": "Hamal"
                       }]
                    }""".decodeJson())
            .awaitCredentialOffer(ctx.malathi, ctx.issuerDid!!)
            .awaitIssuedCredential(ctx.malathi, ctx.issuerDid!!)

        // Malathi MarriageCertificate =================================================================================

        MessageExchange()
            .withConnection(ctx.malathiGov!!)
            .also {
                val pcon = it.getConnection()
                ctx.issuerDid = pcon.theirDid
                ctx.holderDid = pcon.myDid
            }

            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                issuerDid = ctx.issuerDid!!,
                holder = ctx.malathi,
                template = "MarriageCertificate",
                subjectData = """{
                    "spouse": [
                        {
                          "id": "${ctx.malathiGov!!.myDid}",
                          "givenName": "Malathi",
                          "familyName": "Hamal"
                        },
                        {
                          "id": "${ctx.rajeshGov!!.myDid}",
                          "givenName": "Rajesh",
                          "familyName": "Hamal"
                        }]
                    }""".decodeJson())
            .awaitCredentialOffer(ctx.malathi, ctx.issuerDid!!)
            .awaitIssuedCredential(ctx.malathi, ctx.issuerDid!!)

        // Malathi TravelPermission ====================================================================================

        MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(ctx.rajesh)
            .receiveOutOfBandInvitation(ctx.malathi)

            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                ctx.malathiRaj = pcon
                ctx.issuerDid = pcon.theirDid
                ctx.holderDid = pcon.myDid
            }

            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                issuerDid = ctx.issuerDid!!,
                holder = ctx.malathi,
                template = "TravelPermission",
                subjectData = """{
                    "id": "${ctx.malathiGov!!.myDid.uri}",
                    "minor": "${ctx.anandDid!!.uri}",
                    "location": {
                        "type": "Country",
                        "address": {
                            "addressCountry": "CA"
                        }}
                    }""".decodeJson())
            .awaitCredentialOffer(ctx.malathi, ctx.issuerDid!!)
            .awaitIssuedCredential(ctx.malathi, ctx.issuerDid!!)
   }
}
