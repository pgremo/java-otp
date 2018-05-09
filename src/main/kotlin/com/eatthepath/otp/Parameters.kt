package com.eatthepath.otp

import com.eatthepath.otp.Algorithm.HmacSHA1
import org.apache.commons.codec.binary.Base32
import java.net.URI
import java.util.*
import java.util.regex.Pattern
import javax.crypto.spec.SecretKeySpec

val base32 = Base32()

internal class Parameters(uri: URI) {
    private val type: Type
    private val label: String
    private val secret: SecretKeySpec
    private val issuer: String
    private val algorithm: Algorithm
    private val digits: Int
    private val counter: Int
    private val period: Int

    init {
        val query = Pattern.compile("&").split(uri.query)
                .map { it.split("=") }
                .associateBy({ it[0].toLowerCase() }, { it[1] })

        type = Type.valueOf(uri.authority.toLowerCase())
        label = uri.path.substring(1)
        secret = Optional.ofNullable(query["secret"])
                .map<ByteArray> { base32.decode(it) }
                .map { x -> SecretKeySpec(x, "RAW") }
                .orElseThrow { IllegalArgumentException("secret is required") }
        issuer = Optional.ofNullable(query["issuer"])
                .or {
                    Optional.of(label)
                            .map { l -> l.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray() }
                            .filter { l -> l.size > 1 }
                            .map { l -> l[1] }
                }
                .orElseThrow { IllegalArgumentException("issuer is required") }
        algorithm = Optional.ofNullable(query["algorithm"])
                .map { x -> "Hmac$x" }
                .map<Algorithm> { Algorithm.valueOf(it) }
                .orElse(HmacSHA1)
        digits = Optional.ofNullable(query["digits"])
                .map<Int> { Integer.valueOf(it) }
                .orElse(6)
        counter = Optional.ofNullable(query["counter"])
                .map<Int> { Integer.valueOf(it) }
                .orElse(0)
        period = Optional.ofNullable(query["period"])
                .map<Int> { Integer.valueOf(it) }
                .orElse(30)
    }

    override fun toString(): String {
        return "Parameters{" +
                "type=" + type +
                ", label='" + label + '\''.toString() +
                ", secret=" + secret +
                ", issuer='" + issuer + '\''.toString() +
                ", algorithm=" + algorithm +
                ", digits=" + digits +
                ", counter=" + counter +
                ", period=" + period +
                '}'.toString()
    }
}
