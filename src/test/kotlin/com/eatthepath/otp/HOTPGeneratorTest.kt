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

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.NoSuchAlgorithmException

import com.eatthepath.otp.Algorithm.HmacSHA256
import java.nio.charset.StandardCharsets.US_ASCII
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows

internal open class HOTPGeneratorTest {

    private val key = SecretKeySpec("12345678901234567890".toByteArray(US_ASCII), "RAW")

    @ParameterizedTest
    @ValueSource(ints = [5, 9])
    fun testHmacOneTimePasswordGeneratorWithShortPasswordLength(length: Int) {
        assertThrows(IllegalArgumentException::class.java) { HOTPGenerator(length) }
    }

    @Test
    @Throws(NoSuchAlgorithmException::class)
    fun testGetPasswordLength() {
        assertEquals(7, HOTPGenerator(7).passwordLength)
    }

    @Test
    @Throws(NoSuchAlgorithmException::class)
    fun testGetAlgorithm() {
        assertEquals(HmacSHA256, HOTPGenerator(6, HmacSHA256).algorithm)
    }

    /**
     * Tests generation of one-time passwords using the test vectors from
     * [RFC&nbsp;4226, Appendix D](https://tools.ietf.org/html/rfc4226#appendix-D).
     */
    @ParameterizedTest
    @CsvSource("0, 755224", "1, 287082", "2, 359152", "3, 969429", "4, 338314", "5, 254676", "6, 287922", "7, 162583", "8, 399871", "9, 520489")
    @Throws(Exception::class)
    fun testGenerateOneTimePassword(counter: Int, expectedOneTimePassword: Int) {
        assertEquals(expectedOneTimePassword, HOTPGenerator().generateOneTimePassword(key, counter.toLong()))
    }
}
