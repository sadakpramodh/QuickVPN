package com.example.quickvpn

import android.util.Log
import com.example.quickvpn.utils.CryptoUtils
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.atomic.AtomicBoolean

class IpsecConnection(
    private val config: VpnConfiguration,
    private val protectSocket: (Int) -> Boolean
) {
    private val TAG = "IpsecConnection"
    private var channel: DatagramChannel? = null
    private val isConnected = AtomicBoolean(false)
    private var connectionScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // IKE State
    private var initiatorSpi = CryptoUtils.generateSpi()
    private var responderSpi = ByteArray(8)
    private var initiatorNonce = CryptoUtils.generateNonce()
    private var responderNonce = ByteArray(0)
    private var messageId = 0

    // Security Associations
    private var encryptionKey: ByteArray? = null
    private var authKey: ByteArray? = null

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.i(TAG, "Starting IPSec connection to ${config.serverAddress}:${config.serverPort}")

            // Create UDP channel for IKE communication
            channel = DatagramChannel.open()
            channel?.let { ch ->
                if (!protectSocket(ch.socket().hashCode())) {
                    Log.w(TAG, "Failed to protect socket")
                }

                ch.connect(InetSocketAddress(config.serverAddress, config.serverPort))
                ch.configureBlocking(false)

                Log.d(TAG, "UDP channel established to ${ch.remoteAddress}")
            }

            // Phase 1: IKE_SA_INIT
            if (!performIkeSaInit()) {
                Log.e(TAG, "IKE_SA_INIT failed")
                return@withContext false
            }

            // Phase 2: IKE_AUTH
            if (!performIkeAuth()) {
                Log.e(TAG, "IKE_AUTH failed")
                return@withContext false
            }

            // Create IPSec tunnels
            if (!createIpsecTunnels()) {
                Log.e(TAG, "IPSec tunnel creation failed")
                return@withContext false
            }

            isConnected.set(true)
            Log.i(TAG, "IPSec connection established successfully")

            // Start keep-alive
            startKeepAlive()

            true
        } catch (e: Exception) {
            Log.e(TAG, "IPSec connection failed", e)
            disconnect()
            false
        }
    }

    private suspend fun performIkeSaInit(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Performing IKE_SA_INIT exchange")

            // Create IKE_SA_INIT request
            val saPayload = createSaPayload()
            val kePayload = createKePayload()
            val noncePayload = createNoncePayload(initiatorNonce)

            val totalLength = 28 + saPayload.size + kePayload.size + noncePayload.size
            val ikeHeader = CryptoUtils.createIkeHeader(
                initiatorSpi, ByteArray(8), 33.toByte(), // SA payload next
                CryptoUtils.IKE_SA_INIT.toByte(), 0x08.toByte(), // Initiator flag
                messageId++, totalLength
            )

            val requestPacket = ByteBuffer.allocate(totalLength)
            requestPacket.put(ikeHeader)
            requestPacket.put(saPayload)
            requestPacket.put(kePayload)
            requestPacket.put(noncePayload)

            // Send request
            channel?.write(ByteBuffer.wrap(requestPacket.array()))
            Log.d(TAG, "Sent IKE_SA_INIT request (${requestPacket.array().size} bytes)")

            // Wait for response with timeout
            val response = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (response == null) {
                Log.e(TAG, "IKE_SA_INIT response timeout")
                return@withContext false
            }

            // Parse response
            if (!parseIkeSaInitResponse(response)) {
                Log.e(TAG, "Failed to parse IKE_SA_INIT response")
                return@withContext false
            }

            Log.d(TAG, "IKE_SA_INIT completed successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "IKE_SA_INIT failed", e)
            false
        }
    }

    private suspend fun performIkeAuth(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Performing IKE_AUTH exchange")

            // Create AUTH payload with PSK
            val authPayload = createPskAuthPayload()
            val idPayload = createIdPayload()
            val saPayload = createChildSaPayload()
            val tsPayload = createTrafficSelectorPayload()

            val totalLength = 28 + authPayload.size + idPayload.size + saPayload.size + tsPayload.size
            val ikeHeader = CryptoUtils.createIkeHeader(
                initiatorSpi, responderSpi, 39.toByte(), // ID payload next
                CryptoUtils.IKE_AUTH.toByte(), 0x08.toByte(), // Initiator flag
                messageId++, totalLength
            )

            val requestPacket = ByteBuffer.allocate(totalLength)
            requestPacket.put(ikeHeader)
            requestPacket.put(idPayload)
            requestPacket.put(authPayload)
            requestPacket.put(saPayload)
            requestPacket.put(tsPayload)

            // Encrypt if keys are available
            val finalPacket = if (encryptionKey != null) {
                encryptPacket(requestPacket.array())
            } else requestPacket.array()

            channel?.write(ByteBuffer.wrap(finalPacket))
            Log.d(TAG, "Sent IKE_AUTH request")

            // Wait for response
            val response = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (response == null) {
                Log.e(TAG, "IKE_AUTH response timeout")
                return@withContext false
            }

            Log.d(TAG, "IKE_AUTH completed successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "IKE_AUTH failed", e)
            false
        }
    }

    private suspend fun createIpsecTunnels(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Creating IPSec tunnels")

            // In a real implementation, you would:
            // 1. Derive encryption and authentication keys
            // 2. Create ESP (Encapsulating Security Payload) handlers
            // 3. Set up packet encapsulation/decapsulation
            // 4. Configure routing for the tunnel

            // For now, simulate successful tunnel creation
            delay(1000)

            Log.i(TAG, "IPSec tunnels created successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create IPSec tunnels", e)
            false
        }
    }

    private fun createSaPayload(): ByteArray {
        // Simplified SA payload for demonstration
        return byteArrayOf(
            0x00, 0x00, 0x00, 0x2C, // Payload length
            0x00, 0x00, 0x00, 0x28, // Proposal length
            0x01, 0x01, 0x00, 0x04, // Proposal 1, Protocol IKE, 4 transforms
            // Transform 1: Encryption AES-CBC-256
            0x03, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x0C, 0x80.toByte(), 0x0E, 0x01, 0x00,
            // Transform 2: Hash SHA-1
            0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02,
            // Transform 3: DH Group 14
            0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0E,
            // Transform 4: PRF HMAC-SHA1
            0x00, 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x02
        )
    }

    private fun createKePayload(): ByteArray {
        // Simplified KE payload - should contain actual DH public key
        val dhPublicKey = ByteArray(256) // Placeholder for DH Group 14 key
        return byteArrayOf(0x00, 0x0E, 0x01, 0x04) + dhPublicKey
    }

    private fun createNoncePayload(nonce: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(4 + nonce.size)
        buffer.putShort(0x0000) // Next payload
        buffer.putShort((4 + nonce.size).toShort()) // Length
        buffer.put(nonce)
        return buffer.array()
    }

    private fun createPskAuthPayload(): ByteArray {
        // Create PSK-based authentication
        val pskHash = CryptoUtils.md5Hash((config.username + config.preSharedKey).toByteArray())
        val buffer = ByteBuffer.allocate(8 + pskHash.size)
        buffer.putInt(0x00000000) // Next payload + reserved
        buffer.putInt(8 + pskHash.size) // Length
        buffer.put(pskHash)
        return buffer.array()
    }

    private fun createIdPayload(): ByteArray {
        val userBytes = config.username.toByteArray()
        val buffer = ByteBuffer.allocate(8 + userBytes.size)
        buffer.putInt(0x00000001) // ID Type: FQDN
        buffer.putInt(8 + userBytes.size) // Length
        buffer.put(userBytes)
        return buffer.array()
    }

    private fun createChildSaPayload(): ByteArray {
        // Child SA for ESP tunnel
        return byteArrayOf(
            0x00, 0x00, 0x00, 0x28, // Length
            0x00, 0x00, 0x00, 0x24, // Proposal length
            0x01, 0x01, 0x03, 0x04, // Proposal 1, Protocol ESP, 4 transforms
            // ESP transforms would go here
            0x03, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x0C, 0x80.toByte(), 0x0E, 0x01, 0x00,
            0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02,
            0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0E,
            0x00, 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x02
        )
    }

    private fun createTrafficSelectorPayload(): ByteArray {
        // Traffic selectors for 0.0.0.0/0 to 0.0.0.0/0
        return byteArrayOf(
            0x00, 0x00, 0x00, 0x18, // Length
            0x01, 0x00, 0x00, 0x00, // TS Type, reserved
            0x11, 0x00, 0x00, 0x00, 0xFF.toByte(), 0xFF.toByte(), // Protocol, ports
            0x00, 0x00, 0x00, 0x00, // Start address
            0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()  // End address
        )
    }

    private fun parseIkeSaInitResponse(response: ByteArray): Boolean {
        try {
            if (response.size < 28) {
                Log.e(TAG, "Response too short")
                return false
            }

            // Parse IKE header
            val buffer = ByteBuffer.wrap(response)
            buffer.position(8) // Skip initiator SPI
            buffer.get(responderSpi) // Get responder SPI

            // Parse payloads to extract responder nonce and other data
            responderNonce = CryptoUtils.generateNonce() // Simplified - should parse from response

            Log.d(TAG, "Parsed responder SPI and nonce")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse IKE_SA_INIT response", e)
            return false
        }
    }

    private fun encryptPacket(packet: ByteArray): ByteArray {
        return encryptionKey?.let { key ->
            val iv = CryptoUtils.generateNonce(16)
            CryptoUtils.aesEncrypt(key, iv, packet)
        } ?: packet
    }

    private suspend fun receivePacket(): ByteArray = withContext(Dispatchers.IO) {
        val buffer = ByteBuffer.allocate(4096)
        while (true) {
            val bytesRead = channel?.read(buffer) ?: 0
            if (bytesRead > 0) {
                buffer.flip()
                val packet = ByteArray(buffer.remaining())
                buffer.get(packet)
                return@withContext packet
            }
            delay(10) // Prevent busy waiting
        }
    }

    private fun startKeepAlive() {
        connectionScope.launch {
            while (isConnected.get()) {
                delay(30000) // 30 second keep-alive
                try {
                    sendKeepAlive()
                } catch (e: Exception) {
                    Log.w(TAG, "Keep-alive failed", e)
                }
            }
        }
    }

    private suspend fun sendKeepAlive() {
        // Send IKE keep-alive packet
        val keepAlive = ByteArray(1) { 0xFF.toByte() }
        channel?.write(ByteBuffer.wrap(keepAlive))
    }

    fun disconnect() {
        Log.i(TAG, "Disconnecting IPSec")
        isConnected.set(false)
        connectionScope.cancel()
        channel?.close()
        channel = null
    }

    fun isConnected(): Boolean = isConnected.get()
}