package com.eatthepath.otp

import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.given
import org.jetbrains.spek.api.dsl.it
import org.jetbrains.spek.api.dsl.on
import org.junit.jupiter.api.Assertions.assertEquals
import java.nio.charset.StandardCharsets
import java.security.Key
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.TimeUnit
import javax.crypto.spec.SecretKeySpec


object OTPGeneratorSpec : Spek({

    given("a opt algorithm") {
        data class HOTPData(val counter: Long, val expected: Int)
        on("HOTP") {
            val key = SecretKeySpec("12345678901234567890".toByteArray(StandardCharsets.US_ASCII), "RAW")
            listOf(
                    HOTPData(0, 755224),
                    HOTPData(1, 287082),
                    HOTPData(2, 359152),
                    HOTPData(3, 969429),
                    HOTPData(4, 338314),
                    HOTPData(5, 254676),
                    HOTPData(6, 287922),
                    HOTPData(7, 162583),
                    HOTPData(8, 399871),
                    HOTPData(9, 520489)
            ).forEach { (counter, expected) ->
                it("should generate password for $counter") {
                    assertEquals(expected, OTPGenerator(key).generate(hotp(counter)))
                }
            }
        }
        data class TOTPData(val algorithm: String, val clock: Clock, val expected: Int, val key: Key)
        on("TOTP") {
            val step = TimeUnit.SECONDS.toMillis(30)
            listOf(
                    TOTPData("SHA1", clock(59L), 94287082, key("SHA1")),
                    TOTPData("SHA1", clock(1111111109L), 7081804, key("SHA1")),
                    TOTPData("SHA1", clock(1111111111L), 14050471, key("SHA1")),
                    TOTPData("SHA1", clock(1234567890L), 89005924, key("SHA1")),
                    TOTPData("SHA1", clock(2000000000L), 69279037, key("SHA1")),
                    TOTPData("SHA1", clock(20000000000L), 65353130, key("SHA1")),
                    TOTPData("SHA256", clock(59L), 46119246, key("SHA256")),
                    TOTPData("SHA256", clock(1111111109L), 68084774, key("SHA256")),
                    TOTPData("SHA256", clock(1111111111L), 67062674, key("SHA256")),
                    TOTPData("SHA256", clock(1234567890L), 91819424, key("SHA256")),
                    TOTPData("SHA256", clock(2000000000L), 90698825, key("SHA256")),
                    TOTPData("SHA256", clock(20000000000L), 77737706, key("SHA256")),
                    TOTPData("SHA512", clock(59L), 90693936, key("SHA512")),
                    TOTPData("SHA512", clock(1111111109L), 25091201, key("SHA512")),
                    TOTPData("SHA512", clock(1111111111L), 99943326, key("SHA512")),
                    TOTPData("SHA512", clock(1234567890L), 93441116, key("SHA512")),
                    TOTPData("SHA512", clock(2000000000L), 38618901, key("SHA512")),
                    TOTPData("SHA512", clock(20000000000L), 47863826, key("SHA512"))
            ).forEach { (algorithm, clock, expected, key) ->
                it("should generate password for $algorithm, $clock") {
                    val totp = OTPGenerator(key, 8, algorithm)
                    assertEquals(expected, totp.generate(totp(clock, step)))
                }
            }
        }
    }
})

fun clock(instant: Long): Clock {
    return Clock.fixed(Instant.ofEpochSecond(instant), ZoneId.of("UTC"))
}

val keys = mapOf(
        "SHA1" to "12345678901234567890",
        "SHA256" to "12345678901234567890123456789012",
        "SHA512" to "1234567890123456789012345678901234567890123456789012345678901234"
).mapValues { SecretKeySpec(it.value.toByteArray(StandardCharsets.US_ASCII), "RAW") }

fun key(algorithm: String): Key {
    return requireNotNull(keys[algorithm]) { "Unexpected algorithm: $algorithm" }
}
