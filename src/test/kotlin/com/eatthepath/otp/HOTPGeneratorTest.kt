package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.SHA256
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import java.nio.charset.StandardCharsets.US_ASCII
import javax.crypto.spec.SecretKeySpec

internal open class HOTPGeneratorTest {

    private val key = SecretKeySpec("12345678901234567890".toByteArray(US_ASCII), "RAW")

    @ParameterizedTest
    @ValueSource(ints = [5, 9])
    fun testHmacOneTimePasswordGeneratorWithShortPasswordLength(length: Int) {
        assertThrows(IllegalArgumentException::class.java) { HOTPGenerator(key, length) }
    }

    @Test
    fun testGetPasswordLength() {
        assertEquals(7, HOTPGenerator(key, 7).digits)
    }

    @Test
    fun testGetAlgorithm() {
        assertEquals(SHA256, HOTPGenerator(key, 6, SHA256).algorithm)
    }

    @ParameterizedTest
    @CsvSource(
            "0, 755224",
            "1, 287082",
            "2, 359152",
            "3, 969429",
            "4, 338314",
            "5, 254676",
            "6, 287922",
            "7, 162583",
            "8, 399871",
            "9, 520489"
    )
    fun testGenerateOneTimePassword(counter: Long, expectedOneTimePassword: Int) {
        assertEquals(expectedOneTimePassword, HOTPGenerator(key).generateOneTimePassword { counter })
    }
}
