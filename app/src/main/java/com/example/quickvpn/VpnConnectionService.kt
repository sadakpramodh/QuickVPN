package com.example.quickvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.example.quickvpn.utils.NetworkUtils
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

class VpnConnectionService : VpnService() {
    private val TAG = "VpnConnectionService"
    private val NOTIFICATION_ID = 1001
    private val CHANNEL_ID = "vpn_strongswan_channel"

    // Connection components
    private var vpnInterface: ParcelFileDescriptor? = null
    private var ipsecConnection: IpsecConnection? = null
    private var l2tpConnection: L2tpConnection? = null
    private var packetHandler: PacketHandler? = null

    // Service state
    private val isRunning = AtomicBoolean(false)
    private var serviceScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var config: VpnConfiguration? = null

    companion object {
        const val ACTION_CONNECT = "com.example.quickvpn.CONNECT"
        const val ACTION_DISCONNECT = "com.example.quickvpn.DISCONNECT"
        const val ACTION_GET_STATUS = "com.example.quickvpn.GET_STATUS"

        @Volatile
        var isConnected = false
            private set

        @Volatile
        var currentServer = ""
            private set

        @Volatile
        var connectionStatus = "Disconnected"
            private set
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        Log.i(TAG, "VPN service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_CONNECT -> {
                if (!isConnected) {
                    val config = extractConfigFromIntent(intent)
                    if (config != null) {
                        startVpnConnection(config)
                    } else {
                        Log.e(TAG, "Invalid configuration provided")
                        stopSelf()
                    }
                }
                START_STICKY
            }
            ACTION_DISCONNECT -> {
                stopVpnConnection()
                START_NOT_STICKY
            }
            ACTION_GET_STATUS -> {
                // Status is maintained in companion object
                START_NOT_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    private fun extractConfigFromIntent(intent: Intent): VpnConfiguration? {
        return try {
            val server = intent.getStringExtra("server") ?: return null
            val username = intent.getStringExtra("username") ?: return null
            val password = intent.getStringExtra("password") ?: return null
            val psk = intent.getStringExtra("psk") ?: return null

            VpnConfiguration(
                serverAddress = server,
                username = username,
                password = password,
                preSharedKey = psk
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting configuration", e)
            null
        }
    }

    private fun startVpnConnection(config: VpnConfiguration) {
        this.config = config

        serviceScope.launch {
            try {
                connectionStatus = "Initializing..."
                updateNotification("Initializing connection...")

                Log.i(TAG, "Starting strongSwan L2TP/IPSec connection to ${config.serverAddress}")

                // Check network availability
                if (!NetworkUtils.isNetworkAvailable(this@VpnConnectionService)) {
                    throw Exception("No network connectivity available")
                }

                // Establish VPN interface
                connectionStatus = "Creating VPN interface..."
                updateNotification("Creating VPN interface...")

                if (!establishVpnInterface(config)) {
                    throw Exception("Failed to establish VPN interface")
                }

                // Initialize connection components
                connectionStatus = "Initializing IPSec..."
                updateNotification("Initializing IPSec...")

                initializeConnectionComponents(config)

                // Establish IPSec connection
                connectionStatus = "Connecting IPSec..."
                updateNotification("Establishing IPSec connection...")

                if (!connectIpsec()) {
                    throw Exception("IPSec connection failed")
                }

                // Establish L2TP tunnel
                connectionStatus = "Connecting L2TP..."
                updateNotification("Establishing L2TP tunnel...")

                if (!connectL2tp()) {
                    throw Exception("L2TP connection failed")
                }

                // Start packet handling
                connectionStatus = "Starting packet handler..."
                updateNotification("Initializing packet routing...")

                startPacketHandling()

                // Connection successful
                isConnected = true
                currentServer = config.serverAddress
                connectionStatus = "Connected"
                isRunning.set(true)

                startForegroundWithType(createNotification("Connected to ${config.serverAddress}"))

                Log.i(TAG, "strongSwan L2TP/IPSec connection established successfully")

                // Monitor connection health
                startConnectionMonitoring()

            } catch (e: Exception) {
                Log.e(TAG, "VPN connection failed", e)
                connectionStatus = "Failed: ${e.message}"
                updateNotification("Connection failed: ${e.message}")

                cleanup()
                stopSelf()
            }
        }
    }

    private fun establishVpnInterface(config: VpnConfiguration): Boolean {
        return try {
            val builder = Builder()
                .setSession("strongSwan L2TP/IPSec")
                .addAddress(config.localAddress, 32)
                .addRoute("0.0.0.0", 0) // Route all traffic
                .setMtu(config.mtu)

            // Add DNS servers
            config.dnsServers.forEach { dns ->
                builder.addDnsServer(dns)
            }

            // Add search domains if needed
            builder.addSearchDomain("local")

            vpnInterface?.close()
            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                Log.i(TAG, "VPN interface established (fd=${vpnInterface?.fd})")
                Log.d(TAG, "Local address: ${config.localAddress}, MTU: ${config.mtu}")
                true
            } else {
                Log.e(TAG, "Failed to establish VPN interface")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error establishing VPN interface", e)
            false
        }
    }

    private fun initializeConnectionComponents(config: VpnConfiguration) {
        // Initialize IPSec connection
        ipsecConnection = IpsecConnection(config) { socketFd ->
            try {
                protect(socketFd)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to protect socket $socketFd", e)
                false
            }
        }

        // Initialize L2TP connection
        l2tpConnection = L2tpConnection(config) { socketFd ->
            try {
                protect(socketFd)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to protect socket $socketFd", e)
                false
            }
        }

        // Initialize packet handler
        packetHandler = PacketHandler(
            ipsecConnection!!,
            l2tpConnection!!
        )

        Log.d(TAG, "Connection components initialized")
    }

    private suspend fun connectIpsec(): Boolean {
        return ipsecConnection?.connect() ?: false
    }

    private suspend fun connectL2tp(): Boolean {
        return l2tpConnection?.connect() ?: false
    }

    private fun startPacketHandling() {
        vpnInterface?.let { vpnFd ->
            val vpnInput = FileInputStream(vpnFd.fileDescriptor)
            val vpnOutput = FileOutputStream(vpnFd.fileDescriptor)

            packetHandler?.start(vpnInput, vpnOutput)
            Log.d(TAG, "Packet handling started")
        } ?: run {
            throw Exception("VPN interface not available for packet handling")
        }
    }

    private fun startConnectionMonitoring() {
        serviceScope.launch {
            while (isRunning.get()) {
                delay(30000) // Check every 30 seconds

                try {
                    // Check connection health
                    val ipsecHealthy = ipsecConnection?.isConnected() ?: false
                    val l2tpHealthy = l2tpConnection?.isConnected() ?: false

                    if (!ipsecHealthy || !l2tpHealthy) {
                        Log.w(TAG, "Connection health check failed - IPSec: $ipsecHealthy, L2TP: $l2tpHealthy")

                        connectionStatus = "Reconnecting..."
                        updateNotification("Connection lost, reconnecting...")

                        // Attempt to reconnect
                        if (!attemptReconnection()) {
                            Log.e(TAG, "Reconnection failed")
                            stopVpnConnection()
                        }
                    }

                    // Log statistics
                    packetHandler?.getStatistics()?.let { stats ->
                        Log.v(TAG, "Packet stats - In queue: ${stats.incomingQueueSize}, Out queue: ${stats.outgoingQueueSize}")
                    }

                } catch (e: Exception) {
                    Log.e(TAG, "Connection monitoring error", e)
                }
            }
        }
    }

    private suspend fun attemptReconnection(): Boolean {
        return try {
            config?.let { conf ->
                // Reconnect IPSec if needed
                if (ipsecConnection?.isConnected() != true) {
                    Log.i(TAG, "Reconnecting IPSec...")
                    if (!connectIpsec()) {
                        return false
                    }
                }

                // Reconnect L2TP if needed
                if (l2tpConnection?.isConnected() != true) {
                    Log.i(TAG, "Reconnecting L2TP...")
                    if (!connectL2tp()) {
                        return false
                    }
                }

                connectionStatus = "Connected"
                updateNotification("Connected to ${conf.serverAddress}")
                Log.i(TAG, "Reconnection successful")
                true
            } ?: false
        } catch (e: Exception) {
            Log.e(TAG, "Reconnection failed", e)
            false
        }
    }

    private fun stopVpnConnection() {
        Log.i(TAG, "Stopping VPN connection")

        isRunning.set(false)
        isConnected = false
        currentServer = ""
        connectionStatus = "Disconnecting..."

        cleanup()

        connectionStatus = "Disconnected"
        stopForeground(true)
        stopSelf()

        Log.i(TAG, "VPN connection stopped")
    }

    private fun cleanup() {
        try {
            // Stop packet handler
            packetHandler?.stop()
            packetHandler = null

            // Disconnect L2TP
            l2tpConnection?.disconnect()
            l2tpConnection = null

            // Disconnect IPSec
            ipsecConnection?.disconnect()
            ipsecConnection = null

            // Close VPN interface
            vpnInterface?.close()
            vpnInterface = null

            // Cancel service coroutines
            serviceScope.cancel()
            serviceScope = CoroutineScope(Dispatchers.Main + SupervisorJob())

            Log.d(TAG, "Cleanup completed")
        } catch (e: Exception) {
            Log.e(TAG, "Error during cleanup", e)
        }
    }

    private fun startForegroundWithType(notification: Notification) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error starting foreground service", e)
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "strongSwan VPN Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "strongSwan L2TP/IPSec VPN connection status"
                setShowBadge(false)
                enableVibration(false)
                enableLights(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(message: String): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("strongSwan VPN")
                .setContentText(message)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .setShowWhen(false)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("strongSwan VPN")
                .setContentText(message)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .setShowWhen(false)
                .build()
        }
    }

    private fun updateNotification(message: String) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager?.notify(NOTIFICATION_ID, createNotification(message))
    }

    override fun onDestroy() {
        Log.i(TAG, "VPN service destroyed")
        cleanup()
        super.onDestroy()
    }
}