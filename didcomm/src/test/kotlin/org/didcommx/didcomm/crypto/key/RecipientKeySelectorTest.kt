package org.didcommx.didcomm.crypto.key

import org.didcommx.didcomm.KeyAgreementCurveType
import org.didcommx.didcomm.Person
import org.didcommx.didcomm.exceptions.DIDUrlNotFoundException
import org.didcommx.didcomm.exceptions.IncompatibleCryptoException
import org.didcommx.didcomm.exceptions.SecretNotFoundException
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.fixtures.JWM.Companion.BOB_DID
import org.didcommx.didcomm.getKeyAgreementMethodsNotInSecrets
import org.didcommx.didcomm.getKeyAgreementSecrets
import org.didcommx.didcomm.getSecretsResolver
import org.didcommx.didcomm.mock.BobSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RecipientKeySelectorTest {
    @Test
    fun `Test_find_verification_key`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val expected = "did:example:alice#key-2"
        val key = recipientKeySelector.findVerificationKey(expected)
        assertEquals(expected, key.id)
    }

    @Test
    fun `Test_find_anon_crypto_keys`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        val expected = listOf(
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        )

        val keys = recipientKeySelector.findAnonCryptKeys(expected)
        assertContentEquals(expected, keys.toList().map { it.id })
    }

    @Test
    fun `Test_find_second_anon_crypto_key`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        val recipient = listOf(
            "did:example:bob#key-x25519-4",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-5"
        )

        val expected = listOf(
            "did:example:bob#key-x25519-2"
        )

        val keys = recipientKeySelector.findAnonCryptKeys(recipient)
        assertContentEquals(expected, keys.map { it.id }.toList())
    }

    @Test
    fun `Test_find_auth_crypto_keys`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        val sender = "did:example:alice#key-x25519-1"
        val recipient = listOf(
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        )

        val (from, to) = recipientKeySelector.findAuthCryptKeys(sender, recipient)

        val expected = Pair(
            "did:example:alice#key-x25519-1",
            listOf(
                "did:example:bob#key-x25519-1",
                "did:example:bob#key-x25519-2",
                "did:example:bob#key-x25519-3"
            )
        )

        assertEquals(expected.first, from.id)
        assertContentEquals(expected.second, to.toList().map { it.id })
    }

    @Test
    fun `Test_DID_is_passed_to_methods`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())

        run {
            val actual = assertFailsWith<IllegalStateException> {
                recipientKeySelector.findVerificationKey(JWM.ALICE_DID)
            }

            assertEquals(
                "'DID URL' is expected as a signature verification key. Got: did:example:alice",
                actual.message
            )
        }

        run {
            val actual = assertFailsWith<IllegalStateException> {
                recipientKeySelector.findAuthCryptKeys(JWM.ALICE_DID, listOf(JWM.BOB_DID))
            }

            assertEquals("'DID URL' is expected as a sender key. Got: did:example:alice", actual.message)
        }

        run {
            val actual = assertFailsWith<IllegalStateException> {
                recipientKeySelector.findAnonCryptKeys(listOf(JWM.BOB_DID))
            }

            assertEquals("'DID URL' is expected as a recipient key. Got: did:example:bob", actual.message)
        }
    }

    @Test
    fun `Test_key_not_found`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val didUrl = "did:example:bob#key-x25519-4"
        val expected = "The Secret '$didUrl' not found"

        run {
            val actual = assertFailsWith<SecretNotFoundException> {
                recipientKeySelector.findAnonCryptKeys(listOf(didUrl))
                    .also { it.toList() }
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<SecretNotFoundException> {
                recipientKeySelector.findAuthCryptKeys("did:example:alice#key-x25519-1", listOf(didUrl))
                    .also { it.second.toList() }
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_verification_method_not_found`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val expected = "The DID URL 'did:example:bob#key-4' not found in DID Doc 'did:example:bob'"
        val didUrl = "did:example:bob#key-4"

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findAuthCryptKeys(didUrl, listOf(didUrl))
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findVerificationKey(didUrl)
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_DID_Doc_not_resolved`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val did = JWM.NONA_DID
        val didUrl = "$did#key-1"
        val expected = "The DID URL '$didUrl' not found in DID Doc '$did'"

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findVerificationKey(didUrl)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findAuthCryptKeys(didUrl, listOf())
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_empty_DID_Doc`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val didUrl = "${JWM.ELLIE_DID}#key-2"
        val expected = "The DID URL '$didUrl' not found in DID Doc 'did:example:ellie'"

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findVerificationKey(didUrl)
            }

            assertEquals(expected, actual.message)
        }

        run {
            val actual = assertFailsWith<DIDUrlNotFoundException> {
                recipientKeySelector.findAuthCryptKeys(didUrl, listOf())
            }

            assertEquals(expected, actual.message)
        }
    }

    @Test
    fun `Test_incompatible_Crypto`() {
        val recipientKeySelector = RecipientKeySelector(DIDDocResolverMock(), BobSecretResolverMock())
        val bobDIDUrl = "did:example:bob#key-p256-1"
        val charlieDIDUrl = "did:example:charlie#key-x25519-1"

        run {
            val actual = assertFailsWith<IncompatibleCryptoException> {
                recipientKeySelector.findAuthCryptKeys(charlieDIDUrl, listOf(bobDIDUrl)).also { it.second.toList() }
            }

            assertEquals("The recipient '$bobDIDUrl' curve is not compatible to 'X25519'", actual.message)
        }
    }

    @Test
    fun `Test_find_anoncrypt_unpack_recipient_private_keys_positive_single_key`() {
        val keySelector = RecipientKeySelector(DIDDocResolverMock(), getSecretsResolver(Person.BOB))

        for (vm in getKeyAgreementSecrets(Person.BOB)) {
            val res = keySelector.findAnonCryptKeys(listOf(vm.kid)).map { it.jwk.toPublicJWK() }.toList()
            assertContentEquals(listOf(Key.fromSecret(vm).jwk.toPublicJWK()), res)
        }
    }

    @Test
    fun `Test_find_anoncrypt_unpack_recipient_private_keys_all_kids_unknown`() {
        val keySelector = RecipientKeySelector(DIDDocResolverMock(), getSecretsResolver(Person.BOB))

        // TODO DIDUrlNotFoundException
        assertThrows<SecretNotFoundException> {
            val toKids = listOf(
                JWM.BOB_DID + "#unknown-key-1",
                JWM.BOB_DID + "#unknown-key-2"
            )
            keySelector.findAnonCryptKeys(toKids).toList()
        }
    }

    @Test
    fun `Test_find_anoncrypt_unpack_recipient_private_keys_different_curves`() {
        val keySelector = RecipientKeySelector(DIDDocResolverMock(), getSecretsResolver(Person.BOB))

        val secrets = getKeyAgreementSecrets(Person.BOB).map { s -> Key.fromSecret(s) }
        val kids = secrets.map { s -> s.id }
        val expected = secrets.map { it.jwk.toPublicJWK() }
        val res = keySelector.findAnonCryptKeys(kids).map { it.jwk.toPublicJWK() }.toList()

        assertEquals(expected, res)
    }

    data class DifferentCurveTypesTestData(
        val curveType: KeyAgreementCurveType,
    )

    class TestRecipientKeySelectorDifferentCurves {

        companion object {

            @JvmStatic
            fun testRecipientKeySelectorDifferentCurves(): Stream<DifferentCurveTypesTestData> {
                return Stream.of(
                    DifferentCurveTypesTestData(KeyAgreementCurveType.P256),
                    DifferentCurveTypesTestData(KeyAgreementCurveType.P521),
                    DifferentCurveTypesTestData(KeyAgreementCurveType.P384),
                    DifferentCurveTypesTestData(KeyAgreementCurveType.X25519),
                )
            }
        }

        @ParameterizedTest
        @MethodSource("testRecipientKeySelectorDifferentCurves")
        fun `Test_find_anoncrypt_unpack_recipient_private_keys_positive_multiple_keys`(data: DifferentCurveTypesTestData) {
            val keySelector = RecipientKeySelector(DIDDocResolverMock(), getSecretsResolver(Person.BOB))

            val secrets = getKeyAgreementSecrets(Person.BOB, data.curveType)
            val toKids = secrets.map { s -> s.kid }

            val res = keySelector.findAnonCryptKeys(toKids).map { it.jwk.toPublicJWK() }.toList()

            val keySecrets = secrets.map { s -> Key.fromSecret(s).jwk.toPublicJWK() }
            assertContentEquals(keySecrets, res)
        }

        @ParameterizedTest
        @MethodSource("testRecipientKeySelectorDifferentCurves")
        fun `Test_find_anoncrypt_unpack_recipient_private_keys_all_not_in_secrets`(data: DifferentCurveTypesTestData) {
            val keySelector = RecipientKeySelector(DIDDocResolverMock(), getSecretsResolver(Person.BOB))

            val notInSecretKids = getKeyAgreementMethodsNotInSecrets(Person.BOB, data.curveType).map { vm -> vm.id }

            // TODO DIDUrlNotFoundException
            assertThrows<SecretNotFoundException> { keySelector.findAnonCryptKeys(notInSecretKids) }
        }

        @ParameterizedTest
        @MethodSource("testRecipientKeySelectorDifferentCurves")
        fun `test_find_anoncrypt_unpack_recipient_private_keys_known_and_unknown`(data: DifferentCurveTypesTestData) {
            val keySelector = RecipientKeySelector(DIDDocResolverMock(), getSecretsResolver(Person.BOB))

            val secrets = getKeyAgreementSecrets(Person.BOB, data.curveType)
            val validKids = secrets.map { s -> s.kid }
            val toKids = listOf("did:example:unknown1#key-1", "$BOB_DID#unknown-key-2") + validKids

            val res = keySelector.findAnonCryptKeys(toKids).map { it.jwk.toPublicJWK() }

            val keySecrets = secrets.map { s -> Key.fromSecret(s).jwk.toPublicJWK() }
            assertContentEquals(keySecrets, res.toList())
        }

        @ParameterizedTest
        @MethodSource("testRecipientKeySelectorDifferentCurves")
        fun `test_find_anoncrypt_unpack_recipient_private_keys_in_secrets_and_not`(data: DifferentCurveTypesTestData) {
            val keySelector = RecipientKeySelector(DIDDocResolverMock(), getSecretsResolver(Person.BOB))

            val secrets = getKeyAgreementSecrets(Person.BOB, data.curveType)
            val validKids = secrets.map { s -> s.kid }
            val notInSecretKids = getKeyAgreementMethodsNotInSecrets(Person.BOB, data.curveType).map { s -> s.id }
            val kids = notInSecretKids + validKids

            val res = keySelector.findAnonCryptKeys(kids).map { it.jwk.toPublicJWK() }.toList()

            val keySecrets = secrets.map { s -> Key.fromSecret(s).jwk.toPublicJWK() }.toList()
            assertContentEquals(keySecrets, res)
        }
    }
}
