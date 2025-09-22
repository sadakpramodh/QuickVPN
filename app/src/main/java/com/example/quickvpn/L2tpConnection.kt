package com.example.quickvpn

import android.util.Log
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.atomic.AtomicBoolean

class L2tpConnection(
    private val config: VpnConfiguration,
    private val protectSocket: (Int) -> Boolean
) {
    private val TAG = "L2tpConnection"
    private var channel: DatagramChannel? = null
    private val isConnected = AtomicBoolean(false)
    private var connectionScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // L2TP State
    private var tunnelId: Short = 1
    private var sessionId: Short = 1
    private var remoteTunnelId: Short = 0
    private var remoteSessionId: Short = 0
    private var sequenceNumber: Short = 0

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.i(TAG, "Starting L2TP connection to ${config.serverAddress}:${config.l2tpPort}")

            // Create UDP channel for L2TP communication
            channel = DatagramChannel.open()
            channel?.let { ch ->
                if (!protectSocket(ch.socket().hashCode())) {
                    Log.w(TAG, "Failed to protect socket")
                }

                ch.connect(InetSocketAddress(config.serverAddress, config.l2tpPort))
                ch.configureBlocking(false)
            }

            // Establish L2TP tunnel
            if (!establishTunnel()) {
                Log.e(TAG, "L2TP tunnel establishment failed")
                return@withContext false
            }

            // Create L2TP session
            if (!createSession()) {
                Log.e(TAG, "L2TP session creation failed")
                return@withContext false
            }

            // Start PPP negotiation
            if (!negotiatePpp()) {
                Log.e(TAG, "PPP negotiation failed")
                return@withContext false
            }

            isConnected.set(true)
            Log.i(TAG, "L2TP connection established successfully")

            // Start keep-alive
            startKeepAlive()

            true
        } catch (e: Exception) {
            Log.e(TAG, "L2TP connection failed", e)
            disconnect()
            false
        }
    }

    private suspend fun establishTunnel(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Establishing L2TP tunnel")

            // Send Start-Control-Connection-Request (SCCRQ)
            val sccrq = createSccrq()
            channel?.write(ByteBuffer.wrap(sccrq))

            // Wait for Start-Control-Connection-Reply (SCCRP)
            val response = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (response == null) {
                Log.e(TAG, "SCCRP timeout")
                return@withContext false
            }

            if (!parseSccrp(response)) {
                return@withContext false
            }

            // Send Start-Control-Connection-Connected (SCCCN)
            val scccn = createScccn()
            channel?.write(ByteBuffer.wrap(scccn))

            Log.d(TAG, "L2TP tunnel established")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Tunnel establishment failed", e)
            false
        }
    }

    private suspend fun createSession(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Creating L2TP session")

            // Send Incoming-Call-Request (ICRQ)
            val icrq = createIcrq()
            channel?.write(ByteBuffer.wrap(icrq))

            // Wait for Incoming-Call-Reply (ICRP)
            val response = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (response == null) {
                Log.e(TAG, "ICRP timeout")
                return@withContext false
            }

            if (!parseIcrp(response)) {
                return@withContext false
            }

            // Send Incoming-Call-Connected (ICCN)
            val iccn = createIccn()
            channel?.write(ByteBuffer.wrap(iccn))

            Log.d(TAG, "L2TP session created")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Session creation failed", e)
            false
        }
    }

    private suspend fun negotiatePpp(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting PPP negotiation")

            // Send PPP LCP Configure-Request
            val lcpConfigReq = createLcpConfigRequest()
            sendPppPacket(lcpConfigReq)

            // Wait for LCP Configure-Ack
            val response = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (response == null) {
                Log.e(TAG, "LCP Configure-Ack timeout")
                return@withContext false
            }

            // Authenticate using CHAP or PAP
            if (!authenticatePpp()) {
                return@withContext false
            }

            // Configure IPCP
            if (!configureIpcp()) {
                return@withContext false
            }

            Log.d(TAG, "PPP negotiation completed")
            true
        } catch (e: Exception) {
            Log.e(TAG, "PPP negotiation failed", e)
            false
        }
    }

    private suspend fun authenticatePpp(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Authenticating PPP with CHAP")

            // Wait for CHAP Challenge
            val challenge = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (challenge == null) {
                Log.e(TAG, "CHAP Challenge timeout")
                return@withContext false
            }

            // Send CHAP Response
            val chapResponse = createChapResponse(challenge)
            sendPppPacket(chapResponse)

            // Wait for CHAP Success
            val success = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (success == null) {
                Log.e(TAG, "CHAP Success timeout")
                return@withContext false
            }

            Log.d(TAG, "PPP authentication successful")
            true
        } catch (e: Exception) {
            Log.e(TAG, "PPP authentication failed", e)
            false
        }
    }

    private suspend fun configureIpcp(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Configuring IPCP")

            // Send IPCP Configure-Request
            val ipcpConfigReq = createIpcpConfigRequest()
            sendPppPacket(ipcpConfigReq)

            // Wait for IPCP Configure-Ack
            val response = withTimeoutOrNull(5000) {
                receivePacket()
            }

            if (response == null) {
                Log.e(TAG, "IPCP Configure-Ack timeout")
                return@withContext false
            }

            Log.d(TAG, "IPCP configuration completed")
            true
        } catch (e: Exception) {
            Log.e(TAG, "IPCP configuration failed", e)
            false
        }
    }

    // L2TP Packet Creation Methods
    private fun createSccrq(): ByteArray {
        // Create L2TP SCCRQ packet
        return byteArrayOf(
            0xC8.toByte(), 0x02, // Flags and version
            0x00, 0x3C, // Length (60)
            0x00, 0x00, // Tunnel ID
            0x00, 0x00, // Session ID
            0x00, 0x00, // Ns
            0x00, 0x00, // Nr
            // Message Type AVP (SCCRQ = 1)
            0x80.toByte(), 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Host Name AVP
            0x80.toByte(), 0x08, 0x00, 0x00, 0x00, 0x08,
            0x51, 0x75, 0x69, 0x63, 0x6B, 0x56, 0x50, 0x4E, // "QuickVPN"
            // Framing Capabilities AVP
            0x80.toByte(), 0x08, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01
        )
    }

    private fun createScccn(): ByteArray {
        val buffer = ByteBuffer.allocate(32)
        buffer.putShort(0xC802.toShort()) // Flags and version
        buffer.putShort(28) // Length
        buffer.putShort(remoteTunnelId) // Tunnel ID
        buffer.putShort(0) // Session ID
        buffer.putShort(1) // Ns
        buffer.putShort(1) // Nr
        buffer.put(createAvp(0, 0, byteArrayOf(0x00, 0x03))) // Message Type AVP
        return buffer.array()
    }

    private fun createIcrq(): ByteArray {
        val buffer = ByteBuffer.allocate(48)
        buffer.putShort(0xC802.toShort()) // Flags and version
        buffer.putShort(44) // Length
        buffer.putShort(remoteTunnelId) // Tunnel ID
        buffer.putShort(0) // Session ID
        buffer.putShort(2) // Ns
        buffer.putShort(1) // Nr
        buffer.put(createAvp(0, 0, byteArrayOf(0x00, 0x0A))) // Message Type AVP
        buffer.put(createAvp(14, 0, ByteBuffer.allocate(4).putInt(sessionId.toInt()).array())) // Assigned Session ID
        return buffer.array()
    }

    private fun createIccn(): ByteArray {
        val buffer = ByteBuffer.allocate(40)
        buffer.putShort(0xC802.toShort()) // Flags and version
        buffer.putShort(36) // Length
        buffer.putShort(remoteTunnelId) // Tunnel ID
        buffer.putShort(remoteSessionId) // Session ID
        buffer.putShort(3) // Ns
        buffer.putShort(2) // Nr
        buffer.put(createAvp(0, 0, byteArrayOf(0x00, 0x0C))) // Message Type AVP
        return buffer.array()
    }

    private fun createAvp(type: Int, flags: Int, value: ByteArray): ByteArray {
        val length = 6 + value.size
        val result = ByteArray(length)
        result[0] = ((flags shl 10 or length) shr 8).toByte()
        result[1] = (flags shl 10 or length).toByte()
        result[2] = (type shr 24).toByte()
        result[3] = (type shr 16).toByte()
        result[4] = (type shr 8).toByte()
        result[5] = type.toByte()
        System.arraycopy(value, 0, result, 6, value.size)
        return result
    }

    // PPP Packet Creation Methods
    private fun createLcpConfigRequest(): ByteArray {
        return byteArrayOf(
            0xC0.toByte(), 0x21, // LCP Protocol
            0x01, // Configure-Request
            0x01, // Identifier
            0x00, 0x04 // Length
        )
    }

    private fun createChapResponse(challenge: ByteArray): ByteArray {
        // Simplified CHAP response - real implementation would hash challenge + password
        val response = config.password.toByteArray()
        val buffer = ByteBuffer.allocate(response.size + 8)
        buffer.putShort(0xC223.toShort()) // CHAP Protocol
        buffer.put(0x02) // Response
        buffer.put(0x01) // Identifier
        buffer.putShort((response.size + 4).toShort()) // Length
        buffer.put(response.size.toByte()) // Value-Size
        buffer.put(response) // Response Value
        buffer.put(config.username.toByteArray()) // Name
        return buffer.array()
    }

    private fun createIpcpConfigRequest(): ByteArray {
        return byteArrayOf(
            0x80.toByte(), 0x21, // IPCP Protocol
            0x01, // Configure-Request
            0x01, // Identifier
            0x00, 0x0A, // Length
            0x03, 0x06, 0x00, 0x00, 0x00, 0x00 // IP Address option
        )
    }

    private suspend fun sendPppPacket(pppPacket: ByteArray) {
        // Wrap PPP packet in L2TP data message
        val buffer = ByteBuffer.allocate(pppPacket.size + 12)
        buffer.putShort(0x4002.toShort()) // Data flags
        buffer.putShort(remoteTunnelId) // Tunnel ID
        buffer.putShort(remoteSessionId) // Session ID
        buffer.put(pppPacket)

        channel?.write(ByteBuffer.wrap(buffer.array()))
    }

    private fun parseSccrp(response: ByteArray): Boolean {
        // Parse SCCRP to extract remote tunnel ID
        if (response.size < 12) return false

        val buffer = ByteBuffer.wrap(response)
        buffer.position(4) // Skip flags and length
        remoteTunnelId = buffer.short

        Log.d(TAG, "Received remote tunnel ID: $remoteTunnelId")
        return true
    }

    private fun parseIcrp(response: ByteArray): Boolean {
        // Parse ICRP to extract remote session ID
        if (response.size < 12) return false

        val buffer = ByteBuffer.wrap(response)
        buffer.position(6) // Skip to session ID
        remoteSessionId = buffer.short

        Log.d(TAG, "Received remote session ID: $remoteSessionId")
        return true
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
            delay(10)
        }
    }

    private fun startKeepAlive() {
        connectionScope.launch {
            while (isConnected.get()) {
                delay(60000) // 60 second keep-alive
                try {
                    sendKeepAlive()
                } catch (e: Exception) {
                    Log.w(TAG, "Keep-alive failed", e)
                }
            }
        }
    }

    private suspend fun sendKeepAlive() {
        // Send L2TP Hello message
        val hello = createHelloMessage()
        channel?.write(ByteBuffer.wrap(hello))
    }

    private fun createHelloMessage(): ByteArray {
        val buffer = ByteBuffer.allocate(20)
        buffer.putShort(0xC802.toShort()) // Flags
        buffer.putShort(16) // Length
        buffer.putShort(remoteTunnelId)
        buffer.putShort(0) // Session ID
        buffer.putShort(sequenceNumber++) // Ns
        buffer.putShort(0) // Nr
        buffer.put(createAvp(0, 0, byteArrayOf(0x00, 0x06))) // Hello message type
        return buffer.array()
    }

    fun disconnect() {
        Log.i(TAG, "Disconnecting L2TP")
        isConnected.set(false)
        connectionScope.cancel()
        channel?.close()
        channel = null
    }

    fun isConnected(): Boolean = isConnected.get()
}