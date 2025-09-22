package com.example.quickvpn.utils

import android.util.Log
import org.bouncycastle.crypto.digests.MD5Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

object CryptoUtils {
    private const val TAG = "CryptoUtils"

    // IKE Protocol Constants
    const val IKE_SA_INIT = 34
    const val IKE_AUTH = 35

    // Encryption Algorithms
    const val ENCR_AES_CBC = 12
    const val ENCR_3DES = 3

    // Hash Algorithms
    const val AUTH_HMAC_SHA1_96 = 2
    const val AUTH_HMAC_MD5_96 = 1

    fun generateNonce(length: Int = 16): ByteArray {
        val nonce = ByteArray(length)
        SecureRandom().nextBytes(nonce)
        return nonce
    }

    fun generateSpi(): ByteArray {
        val spi = ByteArray(8)
        SecureRandom().nextBytes(spi)
        return spi
    }

    fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray {
        val digest = SHA1Digest()
        val keyParam = KeyParameter(key)
        digest.update(data, 0, data.size)
        val result = ByteArray(digest.digestSize)
        digest.doFinal(result, 0)
        return result.take(12).toByteArray() // IKE uses 96-bit truncation
    }

    fun md5Hash(data: ByteArray): ByteArray {
        val digest = MD5Digest()
        digest.update(data, 0, data.size)
        val result = ByteArray(digest.digestSize)
        digest.doFinal(result, 0)
        return result
    }

    fun deriveKeyMaterial(sharedSecret: ByteArray, nonces: ByteArray, length: Int): ByteArray {
        val generator = PKCS5S2ParametersGenerator(SHA1Digest())
        generator.init(sharedSecret, nonces, 1000)
        val key = generator.generateDerivedParameters(length * 8) as KeyParameter
        return key.key
    }

    fun aesEncrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val secretKey = SecretKeySpec(key, "AES")
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
            cipher.doFinal(data)
        } catch (e: Exception) {
            Log.e(TAG, "AES encryption failed", e)
            data
        }
    }

    fun aesDecrypt(key: ByteArray, iv: ByteArray, encryptedData: ByteArray): ByteArray {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val secretKey = SecretKeySpec(key, "AES")
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
            cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            Log.e(TAG, "AES decryption failed", e)
            encryptedData
        }
    }

    fun createIkeHeader(
        initiatorSpi: ByteArray,
        responderSpi: ByteArray,
        nextPayload: Byte,
        exchangeType: Byte,
        flags: Byte,
        messageId: Int,
        length: Int
    ): ByteArray {
        val buffer = ByteBuffer.allocate(28)
        buffer.put(initiatorSpi) // 8 bytes
        buffer.put(responderSpi) // 8 bytes
        buffer.put(nextPayload)  // 1 byte
        buffer.put(0x20) // Version 2.0
        buffer.put(exchangeType)
        buffer.put(flags)
        buffer.putInt(messageId)
        buffer.putInt(length)
        return buffer.array()
    }
}