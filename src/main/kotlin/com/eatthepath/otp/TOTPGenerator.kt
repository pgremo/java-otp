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

import com.eatthepath.otp.Algorithm.HmacSHA1
import java.security.InvalidKeyException
import java.security.Key
import java.time.Instant
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeUnit.SECONDS
import javax.crypto.Mac

/**
 *
 * Generates time-based one-time passwords (TOTP) as specified in
 * [RFC&nbsp;6238](https://tools.ietf.org/html/rfc6238).
 *
 *
 * `TOTPGenerator` instances are thread-safe and may be shared and re-used across multiple
 * threads.
 *
 * @author [Jon Chambers](https://github.com/jchambers)
 */
class TOTPGenerator
@JvmOverloads constructor(timeStep: Long = 30, timeStepUnit: TimeUnit = SECONDS, passwordLength: Int = DEFAULT_PASSWORD_LENGTH, algorithm: Algorithm = HmacSHA1) : HOTPGenerator(passwordLength, algorithm) {
    /**
     * Returns the time step used by this generator.
     *
     * @return the time step used by this generator in the given units of time
     */
    val timeStep: Long = timeStepUnit.toMillis(timeStep)

    /**
     * Generates a one-time password using the given key and timestamp.
     *
     * @param key       a secret key to be used to generate the password
     * @param timestamp the timestamp for which to generate the password
     * @return an integer representation of a one-time password; callers will need to format the password for display
     * on their own
     * @throws InvalidKeyException if the given key is inappropriate for initializing the [Mac] for this generator
     */
    fun generateOneTimePassword(key: Key, timestamp: Instant): Int {
        return generateOneTimePassword(key, timestamp.toEpochMilli() / timeStep)
    }
}
