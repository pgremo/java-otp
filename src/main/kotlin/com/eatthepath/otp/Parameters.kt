package com.eatthepath.otp

import com.eatthepath.otp.Type.hotp
import org.apache.commons.codec.binary.Base32
import java.net.URI
import javax.crypto.spec.SecretKeySpec

val base32 = Base32()

internal class Parameters(uri: URI) {
    private val type: Type
    private val label: String
    private val secret: SecretKeySpec
    private val issuer: String
    private val algorithm: Algorithm
    private val digits: Int
    private val counter: Int?
    private val period: Int

    init {
        val query = uri.parameters()

        type = Type.valueOf(uri.authority.toLowerCase())
        label = uri.path.substring(1)
        issuer = query["issuer"] ?: label.let {
            val l = label.split(":")
            if (l.size > 1) l[0] else throw IllegalArgumentException("issuer is required")
        }
        secret = query["secret"]?.let { SecretKeySpec(base32.decode(it), "RAW") } ?: throw IllegalArgumentException("secret is required")
        algorithm = Algorithm.valueOf("Hmac" + (query["algorithm"] ?: "SHA1"))
        digits = query["digits"]?.toInt() ?: 6

        // hotp
        counter = query["counter"]?.toInt() ?: if (type == hotp) throw IllegalArgumentException("counter is required") else null

        // totp
        period = query["period"]?.toInt() ?: 30
    }

    override fun toString(): String {
        return "Parameters{" +
                "type=" + type +
                ", label='" + label + '\'' +
                ", secret=" + secret +
                ", issuer='" + issuer + '\'' +
                ", algorithm=" + algorithm +
                ", digits=" + digits +
                ", counter=" + counter +
                ", period=" + period +
                '}'
    }
}

fun URI.parameters(): Map<String, String> = query.split("?")
        .map { it.split("=") }
        .associateBy({ it[0].toLowerCase() }, { it[1] })
