package com.example.quickvpn.utils

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import java.net.InetAddress
import java.net.NetworkInterface
import java.nio.ByteBuffer

object NetworkUtils {
    private const val TAG = "NetworkUtils"

    fun isNetworkAvailable(context: Context): Boolean {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false

        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    fun getLocalIpAddress(): String? {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val networkInterface = interfaces.nextElement()

                if (networkInterface.isLoopback || !networkInterface.isUp) continue

                val addresses = networkInterface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val address = addresses.nextElement()

                    if (!address.isLoopbackAddress &&
                        !address.isLinkLocalAddress &&
                        address is java.net.Inet4Address) {
                        return address.hostAddress
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting local IP address", e)
        }
        return null
    }

    fun parseIpAddress(ipString: String): ByteArray? {
        return try {
            val address = InetAddress.getByName(ipString)
            address.address
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing IP address: $ipString", e)
            null
        }
    }

    fun ipAddressToString(ipBytes: ByteArray): String? {
        return try {
            val address = InetAddress.getByAddress(ipBytes)
            address.hostAddress
        } catch (e: Exception) {
            Log.e(TAG, "Error converting IP bytes to string", e)
            null
        }
    }

    fun calculateChecksum(data: ByteArray, offset: Int = 0, length: Int = data.size): Short {
        var sum = 0L
        var i = offset

        // Sum all 16-bit words
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) + (data[i + 1].toInt() and 0xFF)
            i += 2
        }

        // Add odd byte if present
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        // Add carry bits
        while ((sum shr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        // One's complement
        return (sum xor 0xFFFF).toShort()
    }

    fun isValidIpv4Address(address: String): Boolean {
        val parts = address.split(".")
        if (parts.size != 4) return false

        return parts.all { part ->
            try {
                val num = part.toInt()
                num in 0..255
            } catch (e: NumberFormatException) {
                false
            }
        }
    }

    fun isPrivateIpAddress(address: String): Boolean {
        if (!isValidIpv4Address(address)) return false

        val parts = address.split(".").map { it.toInt() }
        val firstOctet = parts[0]
        val secondOctet = parts[1]

        return when (firstOctet) {
            10 -> true // 10.0.0.0/8
            172 -> secondOctet in 16..31 // 172.16.0.0/12
            192 -> secondOctet == 168 // 192.168.0.0/16
            else -> false
        }
    }

    fun createIpPacket(
        sourceIp: String,
        destinationIp: String,
        protocol: Int,
        payload: ByteArray
    ): ByteArray? {
        return try {
            val sourceBytes = parseIpAddress(sourceIp) ?: return null
            val destBytes = parseIpAddress(destinationIp) ?: return null

            val totalLength = 20 + payload.size // IP header + payload
            val buffer = ByteBuffer.allocate(totalLength)

            // IP Header
            buffer.put(0x45) // Version 4, Header Length 5
            buffer.put(0x00) // Type of Service
            buffer.putShort(totalLength.toShort()) // Total Length
            buffer.putShort(0x0000) // Identification
            buffer.putShort(0x4000) // Flags and Fragment Offset (Don't Fragment)
            buffer.put(0x40) // TTL
            buffer.put(protocol.toByte()) // Protocol
            buffer.putShort(0x0000) // Header Checksum (will calculate)
            buffer.put(sourceBytes) // Source Address
            buffer.put(destBytes) // Destination Address

            // Calculate and set checksum
            val packet = buffer.array()
            val checksum = calculateChecksum(packet, 0, 20)
            ByteBuffer.wrap(packet).putShort(10, checksum)

            // Add payload
            System.arraycopy(payload, 0, packet, 20, payload.size)

            packet
        } catch (e: Exception) {
            Log.e(TAG, "Error creating IP packet", e)
            null
        }
    }

    fun parseIpPacket(packet: ByteArray): IpPacketInfo? {
        return try {
            if (packet.size < 20) return null

            val buffer = ByteBuffer.wrap(packet)
            val versionAndLength = buffer.get().toInt() and 0xFF
            val version = versionAndLength shr 4
            val headerLength = (versionAndLength and 0xF) * 4

            if (version != 4 || packet.size < headerLength) return null

            val tos = buffer.get().toInt() and 0xFF
            val totalLength = buffer.short.toInt() and 0xFFFF
            val identification = buffer.short.toInt() and 0xFFFF
            val flagsAndFragment = buffer.short.toInt() and 0xFFFF
            val ttl = buffer.get().toInt() and 0xFF
            val protocol = buffer.get().toInt() and 0xFF
            val checksum = buffer.short.toInt() and 0xFFFF

            val sourceBytes = ByteArray(4)
            val destBytes = ByteArray(4)
            buffer.get(sourceBytes)
            buffer.get(destBytes)

            val sourceIp = ipAddressToString(sourceBytes)
            val destIp = ipAddressToString(destBytes)

            val payloadSize = totalLength - headerLength
            val payload = if (payloadSize > 0 && packet.size >= headerLength + payloadSize) {
                packet.copyOfRange(headerLength, headerLength + payloadSize)
            } else {
                ByteArray(0)
            }

            IpPacketInfo(
                version = version,
                headerLength = headerLength,
                totalLength = totalLength,
                protocol = protocol,
                sourceIp = sourceIp,
                destinationIp = destIp,
                payload = payload
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing IP packet", e)
            null
        }
    }
}

data class IpPacketInfo(
    val version: Int,
    val headerLength: Int,
    val totalLength: Int,
    val protocol: Int,
    val sourceIp: String?,
    val destinationIp: String?,
    val payload: ByteArray
)