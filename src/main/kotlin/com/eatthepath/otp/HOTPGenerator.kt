/* Copyright (c) 2016 Jon Chambers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. */

package com.eatthepath.otp

import javax.crypto.Mac
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.Key
import java.security.NoSuchAlgorithmException

import com.eatthepath.otp.Algorithm.HmacSHA1
import kotlin.experimental.and

/**
 *
 * Generates HMAC-based one-time passwords (HOTP) as specified in
 * [RFC&nbsp;4226](https://tools.ietf.org/html/rfc4226).
 *
 *
 * `HOTPGenerator` instances are thread-safe and may be shared and re-used across multiple
 * threads.
 *
 * @author [Jon Chambers](https://github.com/jchambers)
 */
open class HOTPGenerator @Throws(NoSuchAlgorithmException::class)
constructor(
        /**
         * Returns the length, in decimal digits, of passwords produced by this generator.
         *
         * @return the length, in decimal digits, of passwords produced by this generator
         */
        val passwordLength: Int,
        /**
         * Returns the name of the HMAC algorithm used by this generator.
         *
         * @return the name of the HMAC algorithm used by this generator
         */
        val algorithm: Algorithm) {
    private val modDivisor: Int

    @Throws(NoSuchAlgorithmException::class)
    @JvmOverloads constructor(passwordLength: Int = DEFAULT_PASSWORD_LENGTH) : this(passwordLength, HmacSHA1) {
    }

    init {
        if (passwordLength < 6 || passwordLength > 8)
            throw IllegalArgumentException("Password length must be between 6 and 8 digits.")
        this.modDivisor = Math.pow(10.0, passwordLength.toDouble()).toInt()
        // Our purpose here is just to throw an exception immediately if the algorithm is bogus.
        Mac.getInstance(algorithm.toString())
    }

    /**
     * Generates a one-time password using the given key and counter value.
     *
     * @param key     a secret key to be used to generate the password
     * @param counter the counter value to be used to generate the password
     * @return an integer representation of a one-time password; callers will need to format the password for display
     * on their own
     * @throws InvalidKeyException if the given key is inappropriate for initializing the [Mac] for this generator
     */
    @Throws(InvalidKeyException::class)
    fun generateOneTimePassword(key: Key, counter: Long): Int {
        val mac: Mac

        try {
            mac = Mac.getInstance(this.algorithm.toString())
            mac.init(key)
        } catch (e: NoSuchAlgorithmException) {
            // This should never happen since we verify that the algorithm is legit in the constructor.
            throw RuntimeException(e)
        }

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

val DEFAULT_PASSWORD_LENGTH = 6