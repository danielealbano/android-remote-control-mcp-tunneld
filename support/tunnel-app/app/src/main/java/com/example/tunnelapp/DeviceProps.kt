package com.example.tunnelapp

import java.security.ProviderException

object DeviceProps {
    fun <T> withFallback(withProps: () -> T, withoutProps: () -> T, onFallback: (ProviderException) -> Unit): T =
        try {
            withProps()
        } catch (e: ProviderException) {
            onFallback(e)
            withoutProps()
        }
}
