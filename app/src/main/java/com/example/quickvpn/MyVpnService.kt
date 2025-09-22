package com.example.quickvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

private const val TAG = "QuickVPN"
private const val NOTIFICATION_ID = 1001
private const val CHANNEL_ID = "vpn_channel"

class MyVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private val isRunning = AtomicBoolean(false)

    companion object {
        const val ACTION_CONNECT = "com.example.quickvpn.CONNECT"
        const val ACTION_DISCONNECT = "com.example.quickvpn.DISCONNECT"

        @Volatile
        var isConnected = false
            private set

        @Volatile
        var currentServer = ""
            private set
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_CONNECT -> {
                if (!isConnected) {
                    startVpn(intent)
                }
                START_STICKY
            }
            ACTION_DISCONNECT -> {
                stopVpn()
                START_NOT_STICKY
            }
            else -> START_NOT_STICKY
        }
    }

    private fun startVpn(intent: Intent) {
        val server = intent.getStringExtra("server") ?: ""
        val username = intent.getStringExtra("username") ?: ""
        val password = intent.getStringExtra("password") ?: ""
        val psk = intent.getStringExtra("psk") ?: ""

        if (server.isBlank()) {
            Log.e(TAG, "No server provided")
            stopSelf()
            return
        }

        Log.i(TAG, "Starting VPN connection to server=$server user=$username")
        Log.d(TAG, "Credentials: passwordProvided=${password.isNotEmpty()} pskProvided=${psk.isNotEmpty()}")

        logActiveNetworkState()

        if (!establishVpnInterface()) {
            Log.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }

        currentServer = server
        isConnected = true

        // Start foreground service with proper type handling
        startForegroundWithType(createNotification("Connected to $server"))

        // Start VPN thread for handling connection
        isRunning.set(true)
        vpnThread = thread(name = "VPN-Thread") {
            try {
                runVpnConnection(server, username, password, psk)
            } catch (e: Exception) {
                Log.e(TAG, "VPN thread error", e)
                stopVpn()
            }
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
            // Fallback to regular startForeground
            try {
                startForeground(NOTIFICATION_ID, notification)
            } catch (e2: Exception) {
                Log.e(TAG, "Fallback foreground service also failed", e2)
            }
        }
    }

    private fun establishVpnInterface(): Boolean {
        return try {
            val builder = Builder()
                .setSession("QuickVPN")
                .addAddress("10.0.0.2", 32)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .addRoute("0.0.0.0", 0)
                .setMtu(1400)

            vpnInterface?.close()
            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                Log.i(TAG, "VPN interface established (fd=${vpnInterface?.fd})")
                Log.d(TAG, "Assigned addresses: 10.0.0.2/32, DNS servers: 8.8.8.8, routes: 0.0.0.0/0")
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

    private fun runVpnConnection(server: String, username: String, password: String, psk: String) {
        var tunnel: DatagramChannel? = null

        try {
            // Create tunnel to VPN server
            tunnel = DatagramChannel.open()
            val protected = protect(tunnel.socket())

            Log.d(TAG, "Connecting UDP tunnel to ${server}:500 on thread ${Thread.currentThread().name} (protectResult=$protected)")

            tunnel.connect(InetSocketAddress(server, 500))

            val remoteAddress = tunnel.remoteAddress
            val localAddress = tunnel.socket().localAddress
            val localPort = tunnel.socket().localPort

            Log.i(TAG, "Tunnel established with $server")
            Log.d(TAG, "Tunnel details: remoteAddress=$remoteAddress localAddress=$localAddress localPort=$localPort")

            // Simulate handshake
            performHandshake(tunnel, username, password, psk)

            // Keep connection alive
            while (isRunning.get() && !Thread.currentThread().isInterrupted) {
                // In a real implementation, this would handle packet forwarding
                Thread.sleep(5000) // Keep connection alive
                Log.v(TAG, "VPN connection active")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error in VPN connection", e)
        } finally {
            try {
                tunnel?.close()
            } catch (e: Exception) {
                Log.w(TAG, "Error closing tunnel", e)
            }
        }
    }

    private fun performHandshake(tunnel: DatagramChannel, username: String, password: String, psk: String) {
        try {
            Log.i(TAG, "Performing VPN handshake (simulated)...")

            // This is a simplified simulation of L2TP/IPSec handshake
            // In a real implementation, you would need:
            // 1. IKE phase 1 and 2
            // 2. IPSec SA establishment
            // 3. L2TP tunnel creation
            // 4. PPP authentication

            Thread.sleep(1000) // Simulate handshake time

            Log.i(TAG, "Handshake completed (simulated)")

        } catch (e: Exception) {
            Log.e(TAG, "Handshake failed", e)
            throw e
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping VPN service")

        isRunning.set(false)
        isConnected = false
        currentServer = ""

        vpnThread?.interrupt()
        vpnThread = null

        vpnInterface?.close()
        vpnInterface = null

        try {
            stopForeground(true)
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping foreground", e)
        }
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN connection status"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(message: String): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("QuickVPN")
                .setContentText(message)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("QuickVPN")
                .setContentText(message)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .build()
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "VPN service destroyed")
        stopVpn()
        super.onDestroy()
    }

    private fun logActiveNetworkState() {
        val hasNetworkStatePermission =
            ContextCompat.checkSelfPermission(
                this,
                android.Manifest.permission.ACCESS_NETWORK_STATE
            ) == PackageManager.PERMISSION_GRANTED

        if (!hasNetworkStatePermission) {
            Log.w(TAG, "ACCESS_NETWORK_STATE permission not granted")
            return
        }

        try {
            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            if (connectivityManager == null) {
                Log.w(TAG, "ConnectivityManager unavailable")
                return
            }

            val activeNetwork = connectivityManager.activeNetwork
            if (activeNetwork == null) {
                Log.w(TAG, "No active network detected")
                return
            }

            val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            capabilities?.let { caps ->
                Log.i(TAG, "Active network capabilities: hasInternet=${caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)} " +
                        "hasValidation=${caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)}")
            }

            val linkProperties = connectivityManager.getLinkProperties(activeNetwork)
            linkProperties?.let { props ->
                Log.d(TAG, "Active network link properties: interface=${props.interfaceName} dns=${props.dnsServers}")
            }

        } catch (e: SecurityException) {
            Log.w(TAG, "Security exception accessing network state", e)
        } catch (e: Exception) {
            Log.w(TAG, "Error accessing network state", e)
        }
    }
}