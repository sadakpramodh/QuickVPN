package com.example.quickvpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel

private const val TAG = "QuickVPN"

class MyVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val server = intent?.getStringExtra("server") ?: ""
        val username = intent?.getStringExtra("username") ?: ""
        val password = intent?.getStringExtra("password") ?: ""
        val psk = intent?.getStringExtra("psk") ?: ""

        if (server.isBlank()) {
            Log.e(TAG, "No server provided in intent extras. Aborting start command.")
            stopSelf()
            return START_NOT_STICKY
        }

        Log.i(TAG, "Connecting to server=$server user=$username")
        Log.d(
            TAG,
            "Credentials summary: passwordProvided=${password.isNotEmpty()} pskProvided=${psk.isNotEmpty()}"
        )
        logActiveNetworkState()

        val builder = Builder()
        builder.setSession("QuickVPN")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)

        vpnInterface?.close()
        vpnInterface = builder.establish()

        if (vpnInterface == null) {
            Log.e(TAG, "Failed to establish VPN interface with provided configuration.")
            stopSelf()
            return START_NOT_STICKY
        } else {
            Log.i(TAG, "VPN interface established (fd=${vpnInterface?.fd})")
            Log.d(TAG, "Assigned addresses: 10.0.0.2/32, DNS servers: 8.8.8.8, routes: 0.0.0.0/0")
        }

        Thread {
            try {
                val tunnel = DatagramChannel.open()
                val protected = protect(tunnel.socket())
                Log.d(
                    TAG,
                    "Connecting UDP tunnel to ${server}:500 on thread ${Thread.currentThread().name} (protectResult=$protected)"
                )
                tunnel.connect(InetSocketAddress(server, 500))
                val remoteAddress = tunnel.remoteAddress
                val localAddress = tunnel.socket().localAddress
                val localPort = tunnel.socket().localPort
                Log.i(TAG, "Tunnel established with $server")
                Log.d(
                    TAG,
                    "Tunnel details: remoteAddress=$remoteAddress localAddress=$localAddress localPort=$localPort"
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error establishing VPN: ${e.message}", e)
            }
        }.start()

        return START_STICKY
    }

    override fun onDestroy() {
        vpnInterface?.close()
        vpnInterface = null
        Log.i(TAG, "VPN disconnected")
        super.onDestroy()
    }

    private fun logActiveNetworkState() {
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        if (connectivityManager == null) {
            Log.w(TAG, "ConnectivityManager unavailable; cannot inspect active network state.")
            return
        }

        val activeNetwork = connectivityManager.activeNetwork
        if (activeNetwork == null) {
            Log.w(TAG, "No active network detected before establishing VPN.")
            return
        }

        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
        val transports = mutableListOf<String>()
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) transports += "WIFI"
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) transports += "CELLULAR"
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) transports += "ETHERNET"
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) transports += "VPN"

        Log.i(
            TAG,
            "Active network capabilities: hasInternet=${capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)} " +
                "hasValidation=${capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)} transports=${if (transports.isEmpty()) "none" else transports.joinToString()}"
        )

        val linkProperties: LinkProperties? = connectivityManager.getLinkProperties(activeNetwork)
        if (linkProperties == null) {
            Log.w(TAG, "Link properties unavailable for active network.")
            return
        }

        Log.d(
            TAG,
            "Active network link properties: interface=${linkProperties.interfaceName} dns=${linkProperties.dnsServers} routes=${linkProperties.routes}"
        )
    }
}
