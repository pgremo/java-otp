package com.eatthepath.otp

import com.eatthepath.otp.Type.hotp
import org.apache.commons.codec.binary.Base32
import java.net.URI
import javax.crypto.spec.SecretKeySpec

val base32 = Base32()

fun parse(uri: URI): Parameters {
    val query = uri.parameters()

    val type = Type.valueOf(uri.authority.toLowerCase())
    val label = uri.path.substring(1)
    val issuer = query["issuer"] ?: label.split(":").let {
        if (it.size > 1) it[0] else throw IllegalArgumentException("issuer is required")
    }
    val secret = requireNotNull(query["secret"]) { "secret is required" }
            .let { SecretKeySpec(base32.decode(it), "RAW") }
    val algorithm = Algorithm.valueOf(query["algorithm"] ?: "SHA1")
    val digits = query["digits"]?.toInt() ?: 6

    // hotp
    val counter = query["counter"]?.toInt()
            ?: if (type == hotp) throw IllegalArgumentException("counter is required") else null

    // totp
    val period = query["period"]?.toInt() ?: 30

    return Parameters(
            type,
            label,
            secret,
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
        val secret: SecretKeySpec,
        val issuer: String,
        val algorithm: Algorithm,
        val digits: Int,
        val counter: Int?,
        val period: Int
)

fun URI.parameters(): Map<String, String> = query.split("?")
        .map { it.split("=") }
        .associateBy({ it[0].toLowerCase() }, { it[1] })
