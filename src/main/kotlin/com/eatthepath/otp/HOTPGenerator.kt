package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.HmacSHA1
import java.nio.ByteBuffer
import java.security.Key
import javax.crypto.Mac
import kotlin.experimental.and
import kotlin.math.pow

open class HOTPGenerator(val digits: Int = 6, val algorithm: Algorithm = HmacSHA1) {
    private val modDivisor: Int

    init {
        if (digits !in 6..8)
            throw IllegalArgumentException("Password length must be 6,7 or 8 digits.")
        modDivisor = 10.0.pow(digits).toInt()
    }

    fun generateOneTimePassword(key: Key, counter: Long): Int {
        val mac: Mac = Mac.getInstance(algorithm.toString())
        mac.init(key)

        val buffer = ByteBuffer
                .allocate(java.lang.Long.BYTES)
                .putLong(0, counter)
        val hmac = mac.doFinal(buffer.array())
        val offset = (hmac[hmac.size - 1] and 0x0f).toInt()

        buffer.put(hmac, offset, Integer.BYTES)

        val hotp = buffer
                .put(hmac, offset, Integer.BYTES)
                .getInt(0) and Integer.MAX_VALUE
        return hotp % modDivisor
    }
}