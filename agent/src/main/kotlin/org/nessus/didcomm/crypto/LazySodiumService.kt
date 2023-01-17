package org.nessus.didcomm.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.exceptions.SodiumException
import com.goterl.lazysodium.interfaces.Box
import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
import org.nessus.didcomm.util.encodeHex

fun java.security.PublicKey.convertEd25519toRaw(): ByteArray {
    require(this.format == "X.509") { "Unexpected format: ${this.format}" }
    val keySize = this.encoded.size
    return this.encoded.sliceArray(keySize - 32 until keySize)
}

fun java.security.KeyPair.convertEd25519toRaw(): KeyPair {
    val publicKey = Key.fromBytes(this.public.convertEd25519toRaw())
    val secretKey = if (this.private != null) run {
        val prvKey = this.private
        require(prvKey.format == "PKCS#8") { "Unexpected format: ${prvKey.format}" }
        val keySize = prvKey.encoded.size
        val secretPart = prvKey.encoded.sliceArray(keySize - 32 until keySize)
        Key.fromBytes(secretPart + publicKey.asBytes)
    } else null
    return KeyPair(publicKey, secretKey)
}

fun java.security.PublicKey.convertEd25519toCurve25519(): Key {
    val edKey = Key.fromBytes(this.convertEd25519toRaw())
    return edKey.convertEd25519toCurve25519()
}

fun Key.convertEd25519toCurve25519(): Key {
    val edPkBytes = this.asBytes
    val curvePkBytes = ByteArray(Sign.CURVE25519_PUBLICKEYBYTES)

    val signNative = lazySodium as Sign.Native
    val pkSuccess: Boolean = signNative.convertPublicKeyEd25519ToCurve25519(curvePkBytes, edPkBytes)
    if (!pkSuccess)
        throw SodiumException("Could not convert this key.")

    return Key.fromBytes(curvePkBytes)
}

fun java.security.KeyPair.convertEd25519toCurve25519(): KeyPair {
    val ed25519RawKeys = this.convertEd25519toRaw()
    val lazySign = lazySodium as Sign.Lazy
    return lazySign.convertKeyPairEd25519ToCurve25519(ed25519RawKeys)
}

/**
 * The lazy variant of Box.cryptoBoxEasy taking a ByteArray as input instead of a String message
 */
fun Box.Lazy.cryptoBoxEasy(message: ByteArray, nonce: ByteArray, keyPair: KeyPair): String {
    val box = lazySodium as Box.Native
    val cipherText = ByteArray(Box.MACBYTES + message.size)
    val encryptResult = box.cryptoBoxEasy(cipherText, message, message.size.toLong(),
        nonce, keyPair.publicKey.asBytes, keyPair.secretKey.asBytes)
    check(encryptResult) { "Cannot encrypt message" }
    return cipherText.encodeHex()
}

/**
 * The lazy variant of Box.cryptoBoxOpenEasy taking a ByteArray as input instead of a String message
 */
fun Box.Lazy.cryptoBoxOpenEasy(cipherText: ByteArray, messageLen: Int, nonce: ByteArray, keyPair: KeyPair): String {
    val box = lazySodium as Box.Native
    val message = ByteArray(messageLen)
    val decryptResult = box.cryptoBoxOpenEasy(message, cipherText, cipherText.size.toLong(), nonce,
        keyPair.publicKey.asBytes, keyPair.secretKey.asBytes)
    check(decryptResult) { "Cannot decrypt message" }
    return message.encodeHex()
}

val lazySodium = LazySodiumJava(SodiumJava())
