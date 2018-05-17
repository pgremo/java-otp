package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.SHA1
import java.net.URI
import java.time.Instant.now
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator

fun main(args: Array<String>) {
    val keyGenerator = KeyGenerator.getInstance("HmacSHA1")
    // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte keys
    keyGenerator.init(512)
    val secretKey = keyGenerator.generateKey()

    val now = now()
    val later = now.plus(30, ChronoUnit.SECONDS)

    val totp = HOTPGenerator(secretKey, 6, SHA1)
    val step = TimeUnit.SECONDS.toMillis(30)
    System.out.format("Current password: %06d\n", totp.generateOneTimePassword { now.toEpochMilli() / step })
    System.out.format("Future password:  %06d\n", totp.generateOneTimePassword { later.toEpochMilli() / step })

    println(parse(URI("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")))
}
