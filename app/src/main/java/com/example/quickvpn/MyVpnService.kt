package com.example.quickvpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel

class MyVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val server = intent?.getStringExtra("server") ?: ""
        val username = intent?.getStringExtra("username") ?: ""
        val password = intent?.getStringExtra("password") ?: ""
        val psk = intent?.getStringExtra("psk") ?: ""

        Log.i("QuickVPN", "Connecting to server=$server user=$username")

        val builder = Builder()
        builder.setSession("QuickVPN")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("8.8.8.8")
            .addRoute("0.0.0.0", 0)

        vpnInterface = builder.establish()

        Thread {
            try {
                val tunnel = DatagramChannel.open()
                tunnel.connect(InetSocketAddress(server, 500))
                Log.i("QuickVPN", "Tunnel established with $server")
            } catch (e: Exception) {
                Log.e("QuickVPN", "Error establishing VPN: ${e.message}")
            }
        }.start()

        return START_STICKY
    }

    override fun onDestroy() {
        vpnInterface?.close()
        vpnInterface = null
        Log.i("QuickVPN", "VPN disconnected")
        super.onDestroy()
    }
}
