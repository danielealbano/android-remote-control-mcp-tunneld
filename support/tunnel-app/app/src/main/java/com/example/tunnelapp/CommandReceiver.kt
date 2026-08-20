package com.example.tunnelapp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

// CommandReceiver maps `am broadcast -a com.example.tunnelapp.<cmd>` intents (+ string extras) to
// TunnelService commands, forwarding the extras.
class CommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val command = when (intent.action) {
            "$PKG.enroll" -> "enroll"
            "$PKG.refresh" -> "refresh"
            "$PKG.stop" -> "stop"
            else -> return
        }
        val svc = Intent(context, TunnelService::class.java).apply {
            putExtra("command", command)
            intent.extras?.let { putExtras(it) }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(svc)
        else context.startService(svc)
    }

    companion object { const val PKG = "com.example.tunnelapp" }
}
