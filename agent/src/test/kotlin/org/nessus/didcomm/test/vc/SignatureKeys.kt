package org.nessus.didcomm.test.vc

import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.binary.Hex
import org.bitcoinj.core.Base58
import org.bitcoinj.core.ECKey
import java.security.KeyFactory
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

object SignatureKeys {
    const val testEd25519PrivateKeyString =
        "43bt2CEvmvm538bQ6YAnpfWTq5xisAB5Kqz7uiob9sabHsZp2HtFEFXRPGa5Mvdhw5xPEABrLduxFu5vt3AViEgF"
    const val testEd25519PublicKeyString = "FyfKP2HvTKqDZQzvyL38yXH7bExmwofxHf2NR5BrcGf1"
    const val testSecp256k1PrivateKeyString = "2ff4e6b73bc4c4c185c68b2c378f6b233978a88d3c8ed03df536f707f084e24e"
    const val testSecp256k1PublicKeyString = "0343f9455cd248e24c262b1341bbe37cea360e1c5ce526e5d1a71373ba6e557018"
    const val testRSAPrivateKeyString = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2lLVmZ9UpU/kq\n" +
            "h8iEwE/S1JZziqWHp+baWtlKS4rFSMRpaPNlLOzvaAQgbGtpa6wx2hG5XnjGxZHJ\n" +
            "/kp5lPRL4jk+uV7ch2LeAgKI7g3C8yTonBIFwlbCZIsUQrJRKcHYK1+IZzT/mtAK\n" +
            "lwS38OfmIz4E2ft+qmgshuSzytcpQiPz6oxWqRNewQp4qKcTbe3XKQyV2w1po4f6\n" +
            "G8a2Lkm3YMycfUmOhd0Nd/G9I//SCNRhvR6S251gVegDrB6SZDIl4ia+DHgzLPUj\n" +
            "iIe2Rj8KnsngyfV6Nnoc2bK+hMT/g65jW4J5i/hTJcVzWzW5TJi2PjPnuqwcaxLh\n" +
            "1DcDYwmzAgMBAAECggEAKp0KuZwCZGL1BLgsVM+N0edMNitl9wN5Hf2WOYDoIqOZ\n" +
            "NAEKzdJuenIMhITJjRFUX05GVL138uyp2js/pqDdY9ipA7rAKThwGuDdNphZHech\n" +
            "9ih3DGEPXs+YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1/BpJthrFxjDRhw9D\n" +
            "xJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEm\n" +
            "tGoJnd9RE4oywKhgN7/TK7wXRlqA4UoRPiH2ACrdU+/cLQL9Jc0u0GqZJK31LDbO\n" +
            "eN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn+CAQKBgQDkEZTVztp//mwXJ+xr\n" +
            "6icgmCjkFm7y4e/PdTJvw4DRr4b1Q87VKEtiNfTBR+FlwUHt/A+2CaZgA3rAoZVx\n" +
            "714wBtfg+WI+Tev4Fylm48qS4uT/AW+BYBDkerDaIS7BctXT97xzaBpS3+HIwLn6\n" +
            "cVzi/QGa/o1Po9+vL5SsrcEpZwKBgQDM8P4H6eueDAX4730Ee9vjtcYpHs43wkIj\n" +
            "onFq/MiS6wxcIHyszJhbzMuzrwvwksDNZnfigyrQU9SfKwHFzmdMXw1vgFnFNnn7\n" +
            "1wd+gqthMjdhayZVbYWkIkUSMyzg1dnbw8GRL1vjON9LYqE12SYJ45hTS0mk1/CY\n" +
            "5Mj3Sp5R1QKBgGia88P5I1ivbg5U3mhEtnuJrr+m1m6KWH6zx1VhuzTxqBnYZwZ3\n" +
            "e9Po4YDBIk2UjVPFV8Nru6awEd5GfpAKdQ3cJannWDsxbDiXDwNFGYWzkcqwct9J\n" +
            "G5Zf+7ugmpxZul+FcicQqXo3e4yjcOnAkxT9bH4VoOTVSeRFE5D8BOujAoGASwz1\n" +
            "+m/vmTFN/pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2d\n" +
            "KZZfV2tbse5N9+JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFX\n" +
            "EZQGUm/BVhoIb2/WPkjav6YSkguCUHt4HRd2YwECgYAGhy4I4Q6r6jIsMAvDMxdT\n" +
            "yA5/cgvVDX8FbCx2gA2iHqLXv2mzGATgldOhZyldlBCq5vyeDATq5H1+l3ebo388\n" +
            "vhPnm9sMPKM8qasva20LaA63H0quk+H5nstBGjgETjycckmvKy0od8WVofYbsnEc\n" +
            "2AwFhUAPK203T2oShq/w6w==\n" +
            "-----END PRIVATE KEY-----\n"
    const val testRSAPublicKeyString = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtpS1ZmfVKVP5KofIhMBP\n" +
            "0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0\n" +
            "S+I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0/5rQCpcEt/Dn\n" +
            "5iM+BNn7fqpoLIbks8rXKUIj8+qMVqkTXsEKeKinE23t1ykMldsNaaOH+hvGti5J\n" +
            "t2DMnH1JjoXdDXfxvSP/0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY/\n" +
            "Cp7J4Mn1ejZ6HNmyvoTE/4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJ\n" +
            "swIDAQAB\n" +
            "-----END PUBLIC KEY-----\n"
    val testEd25519PrivateKey: ByteArray = Base58.decode(testEd25519PrivateKeyString)
    val testEd25519PublicKey: ByteArray = Base58.decode(testEd25519PublicKeyString)
    val testSecp256k1PrivateKey: ECKey = ECKey.fromPrivate(Hex.decodeHex(testSecp256k1PrivateKeyString.toCharArray()))
    val testSecp256k1PublicKey: ECKey = ECKey.fromPublicOnly(Hex.decodeHex(testSecp256k1PublicKeyString.toCharArray()))
    val testRSAPrivateKey: KeyPair = run {
        var pem = testRSAPrivateKeyString
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("\n", "")
        pem = pem.replace("-----END PRIVATE KEY-----", "")
        val encoded = Base64.decodeBase64(pem)
        val spec = PKCS8EncodedKeySpec(encoded)
        val keyFactory = KeyFactory.getInstance("RSA")
        KeyPair(testRSAPublicKey, keyFactory.generatePrivate(spec) as RSAPrivateKey)
    }
    val testRSAPublicKey: RSAPublicKey = run {
        var pem = testRSAPublicKeyString
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("\n", "")
        pem = pem.replace("-----END PUBLIC KEY-----", "")
        val encoded = Base64.decodeBase64(pem)
        val spec = X509EncodedKeySpec(encoded)
        val keyFactory = KeyFactory.getInstance("RSA")
        keyFactory.generatePublic(spec) as RSAPublicKey
    }
}