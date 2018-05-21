package com.eatthepath.otp

import java.nio.ByteBuffer
import java.security.Key
import java.time.Clock
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import kotlin.experimental.and
import kotlin.math.pow

open class OTPGenerator(
        private val key: Key,
        digits: Int = 6,
        private val algorithm: String = "SHA1") {

    private val modDivisor: Int = 10.0.pow(digits).toInt()

    fun generate(counter: () -> Long): Int {
        val mac: Mac = Mac.getInstance("Hmac$algorithm")
        mac.init(key)

        val buffer = ByteBuffer
                .allocate(java.lang.Long.BYTES)
                .putLong(0, counter())
        val hmac = mac.doFinal(buffer.array())
        val offset = (hmac[hmac.size - 1] and 0x0f).toInt()

        buffer.put(hmac, offset, Integer.BYTES)

        val otp = buffer
                .put(hmac, offset, Integer.BYTES)
                .getInt(0) and Integer.MAX_VALUE
        return otp % modDivisor
    }
}

fun hotp(counter: Long): () -> Long{
    val atomic = AtomicLong(counter)
    return atomic::getAndIncrement
}

fun totp(step: Long): () -> Long = { Clock.systemUTC().millis() / step }
fun totp(clock: Clock, step: Long): () -> Long = { clock.millis() / step }