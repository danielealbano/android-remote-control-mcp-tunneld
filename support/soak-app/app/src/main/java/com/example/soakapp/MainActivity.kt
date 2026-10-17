package com.example.soakapp

import android.app.Activity
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Typeface
import android.os.BatteryManager
import android.os.Bundle
import android.os.Debug
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.view.WindowManager
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val screen = Screen()
    private lateinit var text: TextView
    private val tick = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        text = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setPadding(24, 24, 24, 24)
        }
        setContentView(ScrollView(this).apply {
            fitsSystemWindows = true
            addView(text)
        })
        if (savedInstanceState == null && !fromHistory(intent)) Soak.command(filesDir, intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (fromHistory(intent)) return
        Soak.command(filesDir, intent)
    }

    override fun onResume() {
        super.onResume()
        handler.post(tick)
    }

    override fun onPause() {
        handler.removeCallbacks(tick)
        super.onPause()
    }

    private fun refresh() {
        if (Soak.active()) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
        text.text = screen.render(Soak.stats.snapshot(Soak.state(), Soak.phoneCount()), device())
    }

    private fun fromHistory(intent: Intent): Boolean = intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0

    private fun device(): Device {
        val battery = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED), RECEIVER_NOT_EXPORTED)
        val level = battery?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = battery?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val rt = Runtime.getRuntime()
        return Device(
            uptimeMs = SystemClock.elapsedRealtime() - Process.getStartElapsedRealtime(),
            batteryPct = if (level >= 0 && scale > 0) level * 100 / scale else -1,
            temperatureC = (battery?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) ?: 0) / 10.0,
            power = Screen.power(
                battery?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: -1,
                battery?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1,
            ),
            heapUsedMb = (rt.totalMemory() - rt.freeMemory()) shr 20,
            heapMaxMb = rt.maxMemory() shr 20,
            nativeMb = Debug.getNativeHeapAllocatedSize() shr 20,
            threads = Thread.activeCount(),
        )
    }
}
