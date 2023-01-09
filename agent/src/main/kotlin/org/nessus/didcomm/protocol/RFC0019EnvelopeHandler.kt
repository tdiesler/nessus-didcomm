package org.nessus.didcomm.protocol

import com.goterl.lazysodium.interfaces.AEAD
import com.goterl.lazysodium.interfaces.Box
import com.goterl.lazysodium.utils.DetachedEncrypt
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import org.nessus.didcomm.crypto.convertEd25519toCurve25519
import org.nessus.didcomm.crypto.convertEd25519toRaw
import org.nessus.didcomm.crypto.cryptoBoxEasy
import org.nessus.didcomm.crypto.cryptoBoxOpenEasy
import org.nessus.didcomm.crypto.lazySodium
import org.nessus.didcomm.util.decodeBase58
import org.nessus.didcomm.util.decodeBase64Url
import org.nessus.didcomm.util.decodeBase64UrlStr
import org.nessus.didcomm.util.decodeHex
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.util.encodeBase64Url
import org.nessus.didcomm.util.encodeHex
import org.nessus.didcomm.util.encodeJson
import java.security.PublicKey

object RFC0019EnvelopeHandler: ProtocolHandler() {

    fun packRFC0019Envelope(senderKeys: java.security.KeyPair, recipientKey: PublicKey, message: String): String {

        val senderVerkey = senderKeys.public.convertEd25519toRaw().encodeBase58()
        val recipientVerkey = recipientKey.convertEd25519toRaw().encodeBase58()

        val recipientCurve25519Public = recipientKey.convertEd25519toCurve25519()
        val senderCurve25519Keys = senderKeys.convertEd25519toCurve25519()

        // 1. Generate a content encryption key (symmetrical encryption key)
        val aeadLazy = lazySodium as AEAD.Lazy
        val cek: Key = aeadLazy.keygen(AEAD.Method.XCHACHA20_POLY1305_IETF)
        log.info { "cek: ${cek.asHexString}"}

        // 2. Encrypt the CEK for each recipient's public key using Authcrypt

        // 2.1 Set encrypted_key value to base64URLencode(libsodium.crypto_box(my_key, their_vk, cek, cek_iv))
        val boxLazy = lazySodium as Box.Lazy
        val boxNonce = lazySodium.nonce(Box.NONCEBYTES)
        val encryptKeys = KeyPair(recipientCurve25519Public, senderCurve25519Keys.secretKey)
        val encryptedKey = boxLazy.cryptoBoxEasy(cek.asBytes, boxNonce, encryptKeys).decodeHex()

        // 2.2 Set sender value to base64URLencode(libsodium.crypto_box_seal(their_vk, sender_vk_string))
        val senderSealed = boxLazy.cryptoBoxSealEasy(senderVerkey, recipientCurve25519Public).decodeHex()
        log.info { "senderVerkey: $senderVerkey"}

        // 2.3 base64URLencode(cek_iv) and set to iv value in the header
        val cekiv = boxNonce.encodeBase64Url()

        // 3. base64URLencode the protected value
        val protected = """
        {
            "enc": "xchacha20poly1305_ietf",
            "typ": "JWM/1.0",
            "alg": "Authcrypt",
            "recipients": [
                {
                    "encrypted_key": "${encryptedKey.encodeBase64Url()}",
                    "header": {
                        "kid": "$recipientVerkey",
                        "sender": "${senderSealed.encodeBase64Url()}",
                        "iv": "$cekiv"
                    }
                }
            ]
        }            
        """.decodeJson().encodeJson()

        // 4. encrypt the message using libsodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        //    message, protected_value_encoded, iv, cek) this is the ciphertext.
        val aeadNonce = lazySodium.nonce(AEAD.CHACHA20POLY1305_IETF_NPUBBYTES)
        val ciphertext = aeadLazy.encryptDetached(message, protected.toByteArray().encodeBase64Url(),
            null, aeadNonce, cek, AEAD.Method.CHACHA20_POLY1305_IETF)

        // 5. base64URLencode the iv, ciphertext, and tag then serialize the format into the output format listed above.
        return """
            {
                "protected": "${protected.toByteArray().encodeBase64Url()}",
                "ciphertext": "${ciphertext.cipher.encodeBase64Url()}",
                "iv": "${aeadNonce.encodeBase64Url()}",
                "tag": "${ciphertext.mac.encodeBase64Url()}"
            }            
        """.trimIndent()
    }

    fun unpackRFC0019Envelope(envelope: String): String? {

        // 1.Serialize data, so it can be used
        val envelopeMap = envelope.decodeJson()

        // 2. Lookup the kid for each recipient in the wallet
        val protected = envelopeMap["protected"] as? String
        checkNotNull(protected) { "No 'protected' in: $envelope"}

        val protectedMap = protected.decodeBase64UrlStr().decodeJson()
        val recipients = protectedMap["recipients"] as? List<Map<String, Any>>
        checkNotNull(recipients) { "No 'recipients' in: $protectedMap"}

        val keyStore = KeyStoreService.getService()

        val recipient = recipients.firstOrNull {
            val header = it["header"] as? Map<String, Any>
            checkNotNull(header) { "No 'header' in: $it"}
            val kid = header["kid"] as? String
            checkNotNull(kid) { "No 'kid' in: $header"}
            keyStore.getKeyId(kid) != null
        } ?: return null

        val header = recipient["header"] as Map<String, Any>
        val kid = header["kid"] as String
        val recipientKeys = keyStore.load(kid, KeyType.PRIVATE)!!.keyPair
        val recipientCurve25519Keys = recipientKeys!!.convertEd25519toCurve25519()

        // 3. Check if a sender field is used
        val sender64 = header["sender"] as? String
        checkNotNull(sender64) { "anon_decrypt not supported" }

        // 3.1 Decrypt sender verkey using libsodium.crypto_box_seal_open(my_private_key, base64URLdecode(sender))
        val boxLazy = lazySodium as Box.Lazy
        val senderVerkey = boxLazy.cryptoBoxSealOpenEasy(sender64.decodeBase64Url().encodeHex(), recipientCurve25519Keys)
        val senderCurve25519Public = Key.fromBytes(senderVerkey.decodeBase58()).convertEd25519toCurve25519()
        val decryptKeys = KeyPair(senderCurve25519Public, recipientCurve25519Keys.secretKey)
        log.info { "senderVerkey: $senderVerkey"}

        // 3.2 decrypt cek using libsodium.crypto_box_open(my_private_key, sender_verkey, encrypted_key, cek_iv)
        val encryptedKey64 = recipient["encrypted_key"] as? String
        checkNotNull(encryptedKey64) { "No 'encrypted_key' in: $recipient"}
        val cekiv = header["iv"] as? String
        checkNotNull(cekiv) { "No cek 'iv' in: $recipient"}
        val boxNonce = cekiv.decodeBase64Url()
        val encryptedKey = encryptedKey64.decodeBase64Url()
        val cekHex = boxLazy.cryptoBoxOpenEasy(encryptedKey, AEAD.XCHACHA20POLY1305_IETF_KEYBYTES, boxNonce, decryptKeys)
        val cek = Key.fromBytes(cekHex.decodeHex())
        log.info { "cek: ${cek.asBytes.encodeHex()}"}

        // 3.3 decrypt ciphertext using libsodium.crypto_aead_chacha20poly1305_ietf_open_detached(base64URLdecode(ciphertext_bytes), base64URLdecode(protected_data_as_bytes), base64URLdecode(nonce), cek)
        val aeadLazy = lazySodium as AEAD.Lazy
        val ciphertext = envelopeMap["ciphertext"] as? String
        checkNotNull(ciphertext) { "No 'ciphertext' in: $envelope"}
        val iv = envelopeMap["iv"] as? String
        checkNotNull(iv) { "No 'iv' in: $envelope"}
        val tag = envelopeMap["tag"] as? String
        checkNotNull(tag) { "No 'tag' in: $envelope"}
        val encrypted = DetachedEncrypt(ciphertext.decodeBase64Url(), tag.decodeBase64Url())
        val aeadNonce = iv.decodeBase64Url()
        val decrypted = aeadLazy.decryptDetached(encrypted, protected, null, aeadNonce, cek, AEAD.Method.CHACHA20_POLY1305_IETF)

        return decrypted.message.decodeToString()
    }
}