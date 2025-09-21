package com.example.quickvpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var serverInput: EditText
    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var pskInput: EditText
    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        serverInput = findViewById(R.id.editServer)
        usernameInput = findViewById(R.id.editUsername)
        passwordInput = findViewById(R.id.editPassword)
        pskInput = findViewById(R.id.editPsk)
        connectBtn = findViewById(R.id.btnConnect)
        disconnectBtn = findViewById(R.id.btnDisconnect)

        connectBtn.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, 0)
            } else {
                onActivityResult(0, RESULT_OK, null)
            }
        }

        disconnectBtn.setOnClickListener {
            stopService(Intent(this, MyVpnService::class.java))
            Toast.makeText(this, "VPN disconnected", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (resultCode == RESULT_OK) {
            val intent = Intent(this, MyVpnService::class.java).apply {
                putExtra("server", serverInput.text.toString())
                putExtra("username", usernameInput.text.toString())
                putExtra("password", passwordInput.text.toString())
                putExtra("psk", pskInput.text.toString())
            }
            startService(intent)
            Toast.makeText(this, "VPN connecting...", Toast.LENGTH_SHORT).show()
        }
        super.onActivityResult(requestCode, resultCode, data)
    }
}
