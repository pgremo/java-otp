package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.nio.charset.StandardCharsets.US_ASCII
import java.security.Key
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.TimeUnit.SECONDS
import javax.crypto.spec.SecretKeySpec

internal class TOTPGeneratorTest : HOTPGeneratorTest() {

    private val step = SECONDS.toMillis(30)

    @ParameterizedTest
    @MethodSource("testGenerateOneTimePassword")
    fun testGenerateOneTimePassword(algorithm: Algorithm, clock: Clock, expected: Int, key: Key) {
        val totp = HOTPGenerator(key, 8, algorithm)
        assertEquals(expected, totp.generateOneTimePassword { clock.millis() / step })
    }

    companion object {
        @JvmStatic
        fun testGenerateOneTimePassword(): Array<Array<Any>> {
            return arrayOf(
                    arrayOf(SHA1, clock(59L), 94287082, getKeyForAlgorithm(SHA1)),
                    arrayOf(SHA1, clock(1111111109L), 7081804, getKeyForAlgorithm(SHA1)),
                    arrayOf(SHA1, clock(1111111111L), 14050471, getKeyForAlgorithm(SHA1)),
                    arrayOf(SHA1, clock(1234567890L), 89005924, getKeyForAlgorithm(SHA1)),
                    arrayOf(SHA1, clock(2000000000L), 69279037, getKeyForAlgorithm(SHA1)),
                    arrayOf(SHA1, clock(20000000000L), 65353130, getKeyForAlgorithm(SHA1)),
                    arrayOf(SHA256, clock(59L), 46119246, getKeyForAlgorithm(SHA256)),
                    arrayOf(SHA256, clock(1111111109L), 68084774, getKeyForAlgorithm(SHA256)),
                    arrayOf(SHA256, clock(1111111111L), 67062674, getKeyForAlgorithm(SHA256)),
                    arrayOf(SHA256, clock(1234567890L), 91819424, getKeyForAlgorithm(SHA256)),
                    arrayOf(SHA256, clock(2000000000L), 90698825, getKeyForAlgorithm(SHA256)),
                    arrayOf(SHA256, clock(20000000000L), 77737706, getKeyForAlgorithm(SHA256)),
                    arrayOf(SHA512, clock(59L), 90693936, getKeyForAlgorithm(SHA512)),
                    arrayOf(SHA512, clock(1111111109L), 25091201, getKeyForAlgorithm(SHA512)),
                    arrayOf(SHA512, clock(1111111111L), 99943326, getKeyForAlgorithm(SHA512)),
                    arrayOf(SHA512, clock(1234567890L), 93441116, getKeyForAlgorithm(SHA512)),
                    arrayOf(SHA512, clock(2000000000L), 38618901, getKeyForAlgorithm(SHA512)),
                    arrayOf(SHA512, clock(20000000000L), 47863826, getKeyForAlgorithm(SHA512)))
        }
    }
}

fun clock(instant: Long): Clock {
    return Clock.fixed(Instant.ofEpochSecond(instant), ZoneId.of("UTC"));
}

fun getKeyForAlgorithm(algorithm: Algorithm): Key {
    val keyString: String = when (algorithm) {
        SHA1 -> "12345678901234567890"
        SHA256 -> "12345678901234567890123456789012"
        SHA512 -> "1234567890123456789012345678901234567890123456789012345678901234"
        else -> throw IllegalArgumentException("Unexpected algorithm: $algorithm")
    }
    return SecretKeySpec(keyString.toByteArray(US_ASCII), "RAW")
}


