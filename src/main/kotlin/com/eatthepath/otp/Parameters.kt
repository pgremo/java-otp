package com.eatthepath.otp

import com.eatthepath.otp.Type.hotp
import java.net.URI
import java.security.Security

val validAlgorithms = Security.getProviders().flatMap { it.services }.map { it.algorithm }

fun parse(uri: URI): Parameters {

    val type = Type.valueOf(uri.authority.toLowerCase())
    val label = uri.path.substring(1)

    val query = uri.parameters()

    val issuer = query["issuer"] ?: label.split(":").let {
        if (it.size > 1) it[0] else throw IllegalArgumentException("issuer is required")
    }

    val secret = query["secret"]
    requireNotNull(secret) { "secret is required" }

    val algorithm = query["algorithm"] ?: "SHA1"
    require("Hmac$algorithm" in validAlgorithms) { "$algorithm is not supported" }

    val digits = query["digits"]?.toInt() ?: 6
    require(digits in 6..8) { "$digits must be 6,7 or 8 digits." }

    // hotp
    val counter = query["counter"]?.toInt()
            ?: if (type == hotp) throw IllegalArgumentException("counter is required") else null

    // totp
    val period = query["period"]?.toInt() ?: 30

    return Parameters(
            type,
            label,
            secret!!,
            issuer,
            algorithm,
            digits,
            counter,
            period
    )
}

data class Parameters(
        val type: Type,
        val label: String,
        val secret: String,
        val issuer: String,
        val algorithm: String,
        val digits: Int,
        val counter: Int?,
        val period: Int
)

enum class Type {
    totp, hotp
}

fun URI.parameters(): Map<String, String> = query.split("&")
        .map { it.split("=") }
        .associateBy({ it[0].toLowerCase() }) { it[1] }
