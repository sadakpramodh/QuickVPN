package com.example.quickvpn

import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

class PacketHandler(
    private val ipsecConnection: IpsecConnection,
    private val l2tpConnection: L2tpConnection
) {
    private val TAG = "PacketHandler"
    private val isRunning = AtomicBoolean(false)
    private var handlerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Packet queues for processing
    private val incomingQueue: BlockingQueue<ByteArray> = LinkedBlockingQueue()
    private val outgoingQueue: BlockingQueue<ByteArray> = LinkedBlockingQueue()

    // VPN interface streams
    private var vpnInput: FileInputStream? = null
    private var vpnOutput: FileOutputStream? = null

    // ESP (Encapsulating Security Payload) parameters
    private var espSpi: Int = 0x12345678
    private var encryptionKey: ByteArray? = null
    private var authKey: ByteArray? = null
    private var sequenceNumber: Long = 1

    fun start(vpnInput: FileInputStream, vpnOutput: FileOutputStream) {
        this.vpnInput = vpnInput
        this.vpnOutput = vpnOutput

        Log.i(TAG, "Starting packet handler")
        isRunning.set(true)

        // Start packet processing coroutines
        handlerScope.launch { processIncomingPackets() }
        handlerScope.launch { processOutgoingPackets() }
        handlerScope.launch { readFromVpnInterface() }
        handlerScope.launch { writeToVpnInterface() }

        Log.d(TAG, "Packet handler started with 4 processing threads")
    }

    private suspend fun processIncomingPackets() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Started incoming packet processor")

        while (isRunning.get()) {
            try {
                val packet = withTimeoutOrNull(1000) {
                    // In a real implementation, this would receive from the IPSec tunnel
                    incomingQueue.take()
                }

                packet?.let {
                    handleIncomingPacket(it)
                }
            } catch (e: InterruptedException) {
                Log.d(TAG, "Incoming packet processor interrupted")
                break
            } catch (e: Exception) {
                Log.e(TAG, "Error processing incoming packet", e)
            }
        }

        Log.d(TAG, "Incoming packet processor stopped")
    }

    private suspend fun processOutgoingPackets() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Started outgoing packet processor")

        while (isRunning.get()) {
            try {
                val packet = withTimeoutOrNull(1000) {
                    outgoingQueue.take()
                }

                packet?.let {
                    handleOutgoingPacket(it)
                }
            } catch (e: InterruptedException) {
                Log.d(TAG, "Outgoing packet processor interrupted")
                break
            } catch (e: Exception) {
                Log.e(TAG, "Error processing outgoing packet", e)
            }
        }

        Log.d(TAG, "Outgoing packet processor stopped")
    }

    private suspend fun readFromVpnInterface() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Started VPN interface reader")
        val buffer = ByteArray(4096)

        while (isRunning.get()) {
            try {
                vpnInput?.let { input ->
                    val available = input.available()
                    if (available > 0) {
                        val bytesRead = input.read(buffer, 0, minOf(available, buffer.size))
                        if (bytesRead > 0) {
                            val packet = buffer.copyOf(bytesRead)
                            Log.v(TAG, "Read ${bytesRead} bytes from VPN interface")

                            // Queue packet for outgoing processing
                            if (!outgoingQueue.offer(packet)) {
                                Log.w(TAG, "Outgoing queue full, dropping packet")
                            }
                        }
                    } else {
                        delay(10) // Prevent busy waiting
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error reading from VPN interface", e)
                delay(100)
            }
        }

        Log.d(TAG, "VPN interface reader stopped")
    }

    private suspend fun writeToVpnInterface() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Started VPN interface writer")

        while (isRunning.get()) {
            try {
                val packet = withTimeoutOrNull(1000) {
                    incomingQueue.take()
                }

                packet?.let { data ->
                    vpnOutput?.let { output ->
                        output.write(data)
                        output.flush()
                        Log.v(TAG, "Wrote ${data.size} bytes to VPN interface")
                    }
                }
            } catch (e: InterruptedException) {
                Log.d(TAG, "VPN interface writer interrupted")
                break
            } catch (e: Exception) {
                Log.e(TAG, "Error writing to VPN interface", e)
            }
        }

        Log.d(TAG, "VPN interface writer stopped")
    }

    private suspend fun handleIncomingPacket(packet: ByteArray) {
        try {
            Log.v(TAG, "Handling incoming packet (${packet.size} bytes)")

            // 1. Decrypt ESP packet
            val decryptedPacket = decryptEspPacket(packet)
            if (decryptedPacket == null) {
                Log.w(TAG, "Failed to decrypt ESP packet")
                return
            }

            // 2. Remove L2TP header
            val ipPacket = removeL2tpHeader(decryptedPacket)
            if (ipPacket == null) {
                Log.w(TAG, "Failed to remove L2TP header")
                return
            }

            // 3. Remove PPP header
            val finalPacket = removePppHeader(ipPacket)
            if (finalPacket == null) {
                Log.w(TAG, "Failed to remove PPP header")
                return
            }

            // 4. Validate IP packet
            if (validateIpPacket(finalPacket)) {
                // Queue for writing to VPN interface
                if (!incomingQueue.offer(finalPacket)) {
                    Log.w(TAG, "Incoming queue full, dropping packet")
                }
            } else {
                Log.w(TAG, "Invalid IP packet received")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming packet", e)
        }
    }

    private suspend fun handleOutgoingPacket(packet: ByteArray) {
        try {
            Log.v(TAG, "Handling outgoing packet (${packet.size} bytes)")

            // 1. Validate outgoing IP packet
            if (!validateIpPacket(packet)) {
                Log.w(TAG, "Invalid outgoing IP packet")
                return
            }

            // 2. Add PPP header
            val pppPacket = addPppHeader(packet)

            // 3. Add L2TP header
            val l2tpPacket = addL2tpHeader(pppPacket)

            // 4. Encrypt with ESP
            val espPacket = encryptEspPacket(l2tpPacket)
            if (espPacket == null) {
                Log.w(TAG, "Failed to encrypt ESP packet")
                return
            }

            // 5. Send through IPSec tunnel
            sendThroughTunnel(espPacket)

        } catch (e: Exception) {
            Log.e(TAG, "Error handling outgoing packet", e)
        }
    }

    // ESP (Encapsulating Security Payload) Methods
    private fun encryptEspPacket(packet: ByteArray): ByteArray? {
        return try {
            encryptionKey?.let { key ->
                // ESP Header: SPI (4) + Sequence (4) + IV (16) + Payload + Padding + Pad Length (1) + Next Header (1) + ICV (12)
                val iv = com.example.quickvpn.utils.CryptoUtils.generateNonce(16)
                val encrypted = com.example.quickvpn.utils.CryptoUtils.aesEncrypt(key, iv, packet)

                // Create ESP packet
                ByteBuffer.allocate(4 + 4 + 16 + encrypted.size + 12)
                    .putInt(espSpi) // SPI
                    .putLong(sequenceNumber++) // Sequence number (using long for simplicity)
                    .put(iv) // IV
                    .put(encrypted) // Encrypted payload
                    .put(ByteArray(12)) // Authentication data (simplified)
                    .array()
            }
        } catch (e: Exception) {
            Log.e(TAG, "ESP encryption failed", e)
            null
        }
    }

    private fun decryptEspPacket(packet: ByteArray): ByteArray? {
        return try {
            if (packet.size < 36) return null // Minimum ESP packet size

            val buffer = ByteBuffer.wrap(packet)
            val spi = buffer.int
            val sequence = buffer.long
            val iv = ByteArray(16)
            buffer.get(iv)

            val encryptedData = ByteArray(packet.size - 36) // Remaining data minus ICV
            buffer.get(encryptedData)

            encryptionKey?.let { key ->
                com.example.quickvpn.utils.CryptoUtils.aesDecrypt(key, iv, encryptedData)
            }
        } catch (e: Exception) {
            Log.e(TAG, "ESP decryption failed", e)
            null
        }
    }

    // L2TP Methods
    private fun addL2tpHeader(packet: ByteArray): ByteArray {
        // L2TP Data Header: Flags(2) + Length(2) + Tunnel ID(2) + Session ID(2) + Payload
        return ByteBuffer.allocate(8 + packet.size)
            .putShort(0x4000) // Data packet flags
            .putShort((8 + packet.size).toShort()) // Length
            .putShort(1) // Tunnel ID
            .putShort(1) // Session ID
            .put(packet)
            .array()
    }

    private fun removeL2tpHeader(packet: ByteArray): ByteArray? {
        return try {
            if (packet.size < 8) return null

            val buffer = ByteBuffer.wrap(packet)
            val flags = buffer.short
            val length = buffer.short
            val tunnelId = buffer.short
            val sessionId = buffer.short

            // Extract payload
            val payloadSize = packet.size - 8
            val payload = ByteArray(payloadSize)
            buffer.get(payload)

            Log.v(TAG, "Removed L2TP header - Tunnel: $tunnelId, Session: $sessionId")
            payload
        } catch (e: Exception) {
            Log.e(TAG, "Error removing L2TP header", e)
            null
        }
    }

    // PPP Methods
    private fun addPppHeader(packet: ByteArray): ByteArray {
        // PPP Header for IP: Protocol(2) + IP packet
        return ByteBuffer.allocate(2 + packet.size)
            .putShort(0x0021) // IP protocol
            .put(packet)
            .array()
    }

    private fun removePppHeader(packet: ByteArray): ByteArray? {
        return try {
            if (packet.size < 2) return null

            val buffer = ByteBuffer.wrap(packet)
            val protocol = buffer.short

            if (protocol.toInt() != 0x0021) {
                Log.w(TAG, "Non-IP PPP packet: ${protocol.toString(16)}")
                return null
            }

            // Extract IP packet
            val ipPacketSize = packet.size - 2
            val ipPacket = ByteArray(ipPacketSize)
            buffer.get(ipPacket)

            ipPacket
        } catch (e: Exception) {
            Log.e(TAG, "Error removing PPP header", e)
            null
        }
    }

    // IP Packet Validation
    private fun validateIpPacket(packet: ByteArray): Boolean {
        if (packet.size < 20) return false // Minimum IP header size

        val version = (packet[0].toInt() shr 4) and 0xF
        return version == 4 || version == 6 // IPv4 or IPv6
    }

    // Tunnel Communication
    private suspend fun sendThroughTunnel(packet: ByteArray) {
        try {
            // In a real implementation, this would send through the established IPSec tunnel
            // For now, we'll simulate sending
            Log.v(TAG, "Sending ${packet.size} bytes through tunnel")

            // Simulate network delay
            delay(1)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send packet through tunnel", e)
        }
    }

    // Statistics and monitoring
    fun getStatistics(): PacketStatistics {
        return PacketStatistics(
            incomingQueueSize = incomingQueue.size,
            outgoingQueueSize = outgoingQueue.size,
            sequenceNumber = sequenceNumber
        )
    }

    fun stop() {
        Log.i(TAG, "Stopping packet handler")
        isRunning.set(false)
        handlerScope.cancel()

        // Clear queues
        incomingQueue.clear()
        outgoingQueue.clear()

        vpnInput = null
        vpnOutput = null

        Log.d(TAG, "Packet handler stopped")
    }
}

data class PacketStatistics(
    val incomingQueueSize: Int,
    val outgoingQueueSize: Int,
    val sequenceNumber: Long
)