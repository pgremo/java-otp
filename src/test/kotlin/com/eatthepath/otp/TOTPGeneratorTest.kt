package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.nio.charset.StandardCharsets.US_ASCII
import java.security.Key
import java.time.Instant
import java.util.concurrent.TimeUnit.SECONDS
import javax.crypto.spec.SecretKeySpec

internal class TOTPGeneratorTest : HOTPGeneratorTest() {

    @Test
    fun testGetTimeStep() {
        val timeStepSeconds: Long = 97

        val totp = TOTPGenerator(timeStepSeconds, SECONDS)

        assertEquals(timeStepSeconds * 1000, totp.stepMillis)
    }

    @ParameterizedTest
    @MethodSource("testGenerateOneTimePassword")
    fun testGenerateOneTimePassword(algorithm: Algorithm, date: Instant, expectedOneTimePassword: Int, key: Key) {
        val totp = TOTPGenerator(30, SECONDS, 8, algorithm)

        assertEquals(expectedOneTimePassword, totp.generateOneTimePassword(key, date))
    }

    companion object {
        @JvmStatic
        fun testGenerateOneTimePassword(): Array<Array<Any>> {
            return arrayOf(
                    arrayOf<Any>(HmacSHA1, Instant.ofEpochSecond(59L), 94287082, getKeyForAlgorithm(HmacSHA1)),
                    arrayOf<Any>(HmacSHA1, Instant.ofEpochSecond(1111111109L), 7081804, getKeyForAlgorithm(HmacSHA1)),
                    arrayOf<Any>(HmacSHA1, Instant.ofEpochSecond(1111111111L), 14050471, getKeyForAlgorithm(HmacSHA1)),
                    arrayOf<Any>(HmacSHA1, Instant.ofEpochSecond(1234567890L), 89005924, getKeyForAlgorithm(HmacSHA1)),
                    arrayOf<Any>(HmacSHA1, Instant.ofEpochSecond(2000000000L), 69279037, getKeyForAlgorithm(HmacSHA1)),
                    arrayOf<Any>(HmacSHA1, Instant.ofEpochSecond(20000000000L), 65353130, getKeyForAlgorithm(HmacSHA1)),
                    arrayOf<Any>(HmacSHA256, Instant.ofEpochSecond(59L), 46119246, getKeyForAlgorithm(HmacSHA256)),
                    arrayOf<Any>(HmacSHA256, Instant.ofEpochSecond(1111111109L), 68084774, getKeyForAlgorithm(HmacSHA256)),
                    arrayOf<Any>(HmacSHA256, Instant.ofEpochSecond(1111111111L), 67062674, getKeyForAlgorithm(HmacSHA256)),
                    arrayOf<Any>(HmacSHA256, Instant.ofEpochSecond(1234567890L), 91819424, getKeyForAlgorithm(HmacSHA256)),
                    arrayOf<Any>(HmacSHA256, Instant.ofEpochSecond(2000000000L), 90698825, getKeyForAlgorithm(HmacSHA256)),
                    arrayOf<Any>(HmacSHA256, Instant.ofEpochSecond(20000000000L), 77737706, getKeyForAlgorithm(HmacSHA256)),
                    arrayOf<Any>(HmacSHA512, Instant.ofEpochSecond(59L), 90693936, getKeyForAlgorithm(HmacSHA512)),
                    arrayOf<Any>(HmacSHA512, Instant.ofEpochSecond(1111111109L), 25091201, getKeyForAlgorithm(HmacSHA512)),
                    arrayOf<Any>(HmacSHA512, Instant.ofEpochSecond(1111111111L), 99943326, getKeyForAlgorithm(HmacSHA512)),
                    arrayOf<Any>(HmacSHA512, Instant.ofEpochSecond(1234567890L), 93441116, getKeyForAlgorithm(HmacSHA512)),
                    arrayOf<Any>(HmacSHA512, Instant.ofEpochSecond(2000000000L), 38618901, getKeyForAlgorithm(HmacSHA512)),
                    arrayOf<Any>(HmacSHA512, Instant.ofEpochSecond(20000000000L), 47863826, getKeyForAlgorithm(HmacSHA512)))
        }
    }
}

fun getKeyForAlgorithm(algorithm: Algorithm): Key {
    val keyString: String = when (algorithm) {
        HmacSHA1 -> "12345678901234567890"
        HmacSHA256 -> "12345678901234567890123456789012"
        HmacSHA512 -> "1234567890123456789012345678901234567890123456789012345678901234"
        else -> throw IllegalArgumentException(String.format("Unexpected algorithm: %s", algorithm))
    }
    return SecretKeySpec(keyString.toByteArray(US_ASCII), "RAW")
}


