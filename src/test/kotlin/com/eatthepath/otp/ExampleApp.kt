package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.HmacSHA1
import java.net.URI
import java.time.Instant.now
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator

fun main(args: Array<String>) {
    val totp = TOTPGenerator(30, TimeUnit.SECONDS, 6, HmacSHA1)

    val keyGenerator = KeyGenerator.getInstance(totp.algorithm.toString())
    // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte keys
    keyGenerator.init(512)

    val secretKey = keyGenerator.generateKey()
    val now = now()
    val later = now.plus(30, ChronoUnit.SECONDS)

    System.out.format("Current password: %06d\n", totp.generateOneTimePassword(secretKey, now))
    System.out.format("Future password:  %06d\n", totp.generateOneTimePassword(secretKey, later))

    println(Parameters(URI("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")))
}
