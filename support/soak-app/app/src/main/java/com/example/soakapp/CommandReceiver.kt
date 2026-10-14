package com.example.soakapp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class CommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val command = when (intent.action) {
            "$PKG.start" -> "start"
            "$PKG.stop" -> "stop"
            "$PKG.forget" -> "forget"
            else -> return
        }
        val svc = Intent(context, SoakService::class.java).apply {
            putExtra("command", command)
            intent.extras?.let { putExtras(it) }
        }
        context.startForegroundService(svc)
    }

    companion object { const val PKG = "com.example.soakapp" }
}
