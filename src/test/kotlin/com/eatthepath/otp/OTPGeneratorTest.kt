package com.eatthepath.otp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.MethodSource
import java.nio.charset.StandardCharsets.US_ASCII
import java.security.Key
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec

internal open class OTPGeneratorTest {

    private val key = SecretKeySpec("12345678901234567890".toByteArray(US_ASCII), "RAW")

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
        assertEquals(expectedOneTimePassword, OTPGenerator(key).generateOneTimePassword(hotp(counter)))
    }

    private val step = TimeUnit.SECONDS.toMillis(30)

    @ParameterizedTest
    @MethodSource("testGenerateOneTimePassword")
    fun testGenerateOneTimePassword(algorithm: String, clock: Clock, expected: Int, key: Key) {
        val totp = OTPGenerator(key, 8, algorithm)
        assertEquals(expected, totp.generateOneTimePassword(totp(clock, step)))
    }

    companion object {
        @JvmStatic
        fun testGenerateOneTimePassword(): Array<Array<Any>> {
            return arrayOf(
                    arrayOf("SHA1", clock(59L), 94287082, key("SHA1")),
                    arrayOf("SHA1", clock(1111111109L), 7081804, key("SHA1")),
                    arrayOf("SHA1", clock(1111111111L), 14050471, key("SHA1")),
                    arrayOf("SHA1", clock(1234567890L), 89005924, key("SHA1")),
                    arrayOf("SHA1", clock(2000000000L), 69279037, key("SHA1")),
                    arrayOf("SHA1", clock(20000000000L), 65353130, key("SHA1")),
                    arrayOf("SHA256", clock(59L), 46119246, key("SHA256")),
                    arrayOf("SHA256", clock(1111111109L), 68084774, key("SHA256")),
                    arrayOf("SHA256", clock(1111111111L), 67062674, key("SHA256")),
                    arrayOf("SHA256", clock(1234567890L), 91819424, key("SHA256")),
                    arrayOf("SHA256", clock(2000000000L), 90698825, key("SHA256")),
                    arrayOf("SHA256", clock(20000000000L), 77737706, key("SHA256")),
                    arrayOf("SHA512", clock(59L), 90693936, key("SHA512")),
                    arrayOf("SHA512", clock(1111111109L), 25091201, key("SHA512")),
                    arrayOf("SHA512", clock(1111111111L), 99943326, key("SHA512")),
                    arrayOf("SHA512", clock(1234567890L), 93441116, key("SHA512")),
                    arrayOf("SHA512", clock(2000000000L), 38618901, key("SHA512")),
                    arrayOf("SHA512", clock(20000000000L), 47863826, key("SHA512")))
        }
    }
}

fun clock(instant: Long): Clock {
    return Clock.fixed(Instant.ofEpochSecond(instant), ZoneId.of("UTC"));
}

val keys = mapOf(
        "SHA1" to "12345678901234567890",
        "SHA256" to "12345678901234567890123456789012",
        "SHA512" to "1234567890123456789012345678901234567890123456789012345678901234"
).mapValues { SecretKeySpec(it.value.toByteArray(US_ASCII), "RAW") }

fun key(algorithm: String): Key {
    return requireNotNull(keys[algorithm]) { "Unexpected algorithm: $algorithm" }
}

