package com.example.quickvpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var serverInput: EditText
    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var pskInput: EditText
    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button
    private lateinit var statusText: TextView

    private val handler = Handler(Looper.getMainLooper())
    private var statusUpdateRunnable: Runnable? = null

    companion object {
        private const val VPN_REQUEST_CODE = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initializeViews()
        setupClickListeners()
        startStatusUpdates()
    }

    private fun initializeViews() {
        serverInput = findViewById(R.id.editServer)
        usernameInput = findViewById(R.id.editUsername)
        passwordInput = findViewById(R.id.editPassword)
        pskInput = findViewById(R.id.editPsk)
        connectBtn = findViewById(R.id.btnConnect)
        disconnectBtn = findViewById(R.id.btnDisconnect)
        statusText = findViewById(R.id.statusText)

        // Pre-fill with working values
        serverInput.setText("124.123.25.250")
        usernameInput.setText("sadakpramodh")
        passwordInput.setText("Indicom06@")
        pskInput.setText("jN9ZfeXvEo")

        updateUI()
    }

    private fun setupClickListeners() {
        connectBtn.setOnClickListener {
            if (validateInputs()) {
                requestVpnPermission()
            }
        }

        disconnectBtn.setOnClickListener {
            disconnectVpn()
        }
    }

    private fun validateInputs(): Boolean {
        when {
            serverInput.text.toString().trim().isEmpty() -> {
                showError("Server address is required")
                serverInput.requestFocus()
                return false
            }
            usernameInput.text.toString().trim().isEmpty() -> {
                showError("Username is required")
                usernameInput.requestFocus()
                return false
            }
            passwordInput.text.toString().trim().isEmpty() -> {
                showError("Password is required")
                passwordInput.requestFocus()
                return false
            }
            pskInput.text.toString().trim().isEmpty() -> {
                showError("Pre-shared key is required")
                pskInput.requestFocus()
                return false
            }
        }

        // Validate server address format
        val serverAddr = serverInput.text.toString().trim()
        if (!com.example.quickvpn.utils.NetworkUtils.isValidIpv4Address(serverAddr) &&
            !isValidDomain(serverAddr)) {
            showError("Invalid server address format")
            serverInput.requestFocus()
            return false
        }

        return true
    }

    private fun isValidDomain(domain: String): Boolean {
        return domain.matches(Regex("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"))
    }

    private fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            // Permission already granted
            startVpnService()
        }
    }

    private fun startVpnService() {
        val config = VpnConfiguration(
            serverAddress = serverInput.text.toString().trim(),
            username = usernameInput.text.toString().trim(),
            password = passwordInput.text.toString().trim(),
            preSharedKey = pskInput.text.toString().trim()
        )

        if (!config.isValid()) {
            showError("Invalid configuration")
            return
        }

        val intent = Intent(this, VpnConnectionService::class.java).apply {
            action = VpnConnectionService.ACTION_CONNECT
            putExtra("server", config.serverAddress)
            putExtra("username", config.username)
            putExtra("password", config.password)
            putExtra("psk", config.preSharedKey)
        }

        startService(intent)
        Toast.makeText(this, "Starting strongSwan L2TP/IPSec connection...", Toast.LENGTH_SHORT).show()

        // Show progress
        lifecycleScope.launch {
            connectBtn.text = "Connecting..."
            connectBtn.isEnabled = false

            // Wait a bit for connection to start
            delay(2000)
            updateUI()
        }
    }

    private fun disconnectVpn() {
        val intent = Intent(this, VpnConnectionService::class.java).apply {
            action = VpnConnectionService.ACTION_DISCONNECT
        }
        startService(intent)

        Toast.makeText(this, "Disconnecting VPN...", Toast.LENGTH_SHORT).show()

        lifecycleScope.launch {
            disconnectBtn.text = "Disconnecting..."
            disconnectBtn.isEnabled = false

            delay(1000)
            updateUI()
        }
    }

    private fun updateUI() {
        val isConnected = VpnConnectionService.isConnected
        val status = VpnConnectionService.connectionStatus
        val server = VpnConnectionService.currentServer

        // Update button states
        connectBtn.isEnabled = !isConnected
        connectBtn.text = if (isConnected) "Connected" else "Connect"

        disconnectBtn.isEnabled = isConnected
        disconnectBtn.text = if (isConnected) "Disconnect" else "Disconnected"

        // Update status text
        statusText.text = when {
            isConnected -> "Status: Connected to $server\nProtocol: strongSwan L2TP/IPSec"
            status.isNotEmpty() -> "Status: $status"
            else -> "Status: Disconnected"
        }

        // Update status text color
        statusText.setTextColor(
            if (isConnected) {
                getColor(android.R.color.holo_green_dark)
            } else {
                getColor(android.R.color.secondary_text_light)
            }
        )
    }

    private fun startStatusUpdates() {
        statusUpdateRunnable = object : Runnable {
            override fun run() {
                updateUI()
                handler.postDelayed(this, 1000) // Update every second
            }
        }
        handler.post(statusUpdateRunnable!!)
    }

    private fun stopStatusUpdates() {
        statusUpdateRunnable?.let {
            handler.removeCallbacks(it)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                startVpnService()
            } else {
                showError("VPN permission is required to connect")
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateUI()
        startStatusUpdates()
    }

    override fun onPause() {
        super.onPause()
        stopStatusUpdates()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopStatusUpdates()
    }
}