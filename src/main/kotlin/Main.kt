import com.google.common.base.Splitter
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import org.bouncycastle.crypto.params.KDFParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec


@Suppress("SameParameterValue")
private fun encryptMessageOnServer(pemString: String, message: String): ByteArray {
    val bytesPublicKey = pemString.pemStringToBytes()
    val keyPairServer = generateECKeys()
    val publicKeyServer = keyPairServer.public as ECPublicKey
    val publicKeyClientOnServerSide = loadX509PublicKey(bytesPublicKey)
    val privateKeyServer = keyPairServer.private // server_key
    val publicKeyServerLast65Bytes = publicKeyServer.encoded.run { copyOfRange(size - 65, size) } // shared_bytes
    val sharedSecret = getSharedSecret(publicKeyClientOnServerSide, privateKeyServer) // shared_key
    val keyMaterial = deriveKey(sharedSecret, publicKeyServerLast65Bytes) // key
    val aesKey = SecretKeySpec(keyMaterial, "AES")
    val iv = ByteArray(16)
    val encryptedText = encryptString(aesKey, message, iv) // encrypted_text
    val finalMessage = publicKeyServerLast65Bytes + encryptedText
    return Base64.getEncoder().encode(finalMessage)
}

private fun decryptMessageOnClient(keyPair: KeyPair, encryptedMessage: ByteArray): String {
    val encodedMessage = Base64.getDecoder().decode(encryptedMessage)
    val ephemeralKeyBytes = encodedMessage.copyOfRange(0, 65)
    val encryptedData = encodedMessage.copyOfRange(65, encodedMessage.size)
    val publicKeyClient = keyPair.public as ECPublicKey
    val ephemeralPublicKey: PublicKey = loadPublicKey(ephemeralKeyBytes, publicKeyClient.params)
    val sharedSecret = getSharedSecret(ephemeralPublicKey, keyPair.private)
    val keyMaterial = deriveKey(sharedSecret, ephemeralKeyBytes)
    val aesKey = SecretKeySpec(keyMaterial, "AES")
    val iv = ByteArray(16)
    return decryptString(aesKey, encryptedData, iv)
}

fun main() {
    Security.addProvider(BouncyCastleProvider())
    val message = "secret message"
    println("plain text secret message: $message")
    val keyPairClient = generateECKeys()
    val clientPubPemKey = keyPairClient.public.toPemStringFormat()
    val encryptedMessage = encryptMessageOnServer(clientPubPemKey, message)
    val decryptedMessage = decryptMessageOnClient(keyPairClient, encryptedMessage)
    assert(message == decryptedMessage)
    println("decrypted secret message: $decryptedMessage")
}

private fun loadPublicKey(data: ByteArray, ecParameterSpec: ECParameterSpec): PublicKey {
    val publicPoint: ECPoint = ECPointUtil.decodePoint(ecParameterSpec.curve, data)
    val pubKey = ECPublicKeySpec(publicPoint, ecParameterSpec)
    val keyFactory = KeyFactory.getInstance("ECDH")
    return keyFactory.generatePublic(pubKey)
}

private fun loadX509PublicKey(data: ByteArray): PublicKey {
    val spec = X509EncodedKeySpec(data)
    val keyFactory = KeyFactory.getInstance("ECDH")
    return keyFactory.generatePublic(spec)
}

private fun getSharedSecret(ephemeralPublicKey: PublicKey, privateKey: PrivateKey): ByteArray {
    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(privateKey)
    keyAgreement.doPhase(ephemeralPublicKey, true)
    return keyAgreement.generateSecret()
}

fun generateECKeys(): KeyPair {
    val parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    val keyPairGenerator = KeyPairGenerator.getInstance("ECDH")
    keyPairGenerator.initialize(parameterSpec)
    return keyPairGenerator.generateKeyPair()
}

private fun deriveKey(initialSecret: ByteArray, ephemeralKeyBytes: ByteArray): ByteArray {
    val kdfGenerator = KDF2BytesGenerator(SHA256Digest())
    kdfGenerator.init(KDFParameters(initialSecret, ephemeralKeyBytes))
    val kdfOut = ByteArray(16)
    kdfGenerator.generateBytes(kdfOut, 0, 16)
    return kdfOut
}

fun encryptString(key: SecretKey, plainText: String, iv: ByteArray): ByteArray {
    val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, spec)
    return cipher.doFinal(plainText.toByteArray())
}

fun decryptString(key: SecretKey, cipherBytes: ByteArray, iv: ByteArray): String {
    val decryptionKey: Key = SecretKeySpec(key.encoded, key.algorithm)
    val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, decryptionKey, spec)
    return String(cipher.doFinal(cipherBytes))
}

fun PublicKey.toPemStringFormat() = buildString {
    val publicKeyContent = String(Base64.getEncoder().encode(encoded))
    append("$PUB_KEY_HEADER${System.lineSeparator()}")
    for (row in Splitter.fixedLength(64).split(publicKeyContent)) {
        append(row + System.lineSeparator())
    }
    append(PUB_KEY_FOOTER)
}

fun String.pemStringToBytes(): ByteArray {
    val publicKeyPEM: String = replace("-----BEGIN PUBLIC KEY-----", "")
        .replace(System.lineSeparator(), "")
        .replace("-----END PUBLIC KEY-----", "")
    return Base64.getDecoder().decode(publicKeyPEM)
}

private const val GCM_TAG_LENGTH = 128
private const val PUB_KEY_HEADER = "-----BEGIN PUBLIC KEY-----"
private const val PUB_KEY_FOOTER = "-----END PUBLIC KEY-----"