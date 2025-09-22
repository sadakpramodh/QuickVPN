package com.example.quickvpn

data class VpnConfiguration(
    val serverAddress: String,
    val username: String,
    val password: String,
    val preSharedKey: String,
    val serverPort: Int = 500,
    val l2tpPort: Int = 1701,
    val mtu: Int = 1400,
    val dnsServers: List<String> = listOf("8.8.8.8", "8.8.4.4"),
    val localAddress: String = "10.0.0.2",
    val remoteAddress: String = "10.0.0.1"
) {
    fun isValid(): Boolean {
        return serverAddress.isNotBlank() &&
                username.isNotBlank() &&
                password.isNotBlank() &&
                preSharedKey.isNotBlank()
    }
}
