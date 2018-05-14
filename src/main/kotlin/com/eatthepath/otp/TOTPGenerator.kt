package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.HmacSHA1
import java.security.Key
import java.time.Instant
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeUnit.SECONDS

class TOTPGenerator(step: Long = 30, units: TimeUnit = SECONDS, digits: Int = 6, algorithm: Algorithm = HmacSHA1) : HOTPGenerator(digits, algorithm) {
    val stepMillis: Long = units.toMillis(step)

    fun generateOneTimePassword(key: Key, timestamp: Instant): Int =
            generateOneTimePassword(key, timestamp.toEpochMilli() / stepMillis)
}
