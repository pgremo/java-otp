package com.eatthepath.otp;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.eatthepath.otp.Algorithm.HmacSHA1;
import static java.util.stream.Collectors.toMap;

class Parameters {
  private final Type type;
  private final String label;
  private final SecretKeySpec secret;
  private final String issuer;
  private final Algorithm algorithm;
  private final int digits;
  private final int counter;
  private final int period;

  public Parameters(URI uri) {
    Base32 base32 = new Base32();

    Map<String, String> query =
      Pattern.compile("&").splitAsStream(uri.getQuery())
        .map(s -> s.split("="))
        .collect(toMap(s -> s[0].toLowerCase(), s -> s[1]));

    type = Type.valueOf(uri.getAuthority().toLowerCase());
    label = uri.getPath().substring(1);
    secret = Optional.ofNullable(query.get("secret"))
      .map(base32::decode)
      .map(x -> new SecretKeySpec(x, "RAW"))
      .orElseThrow(() -> new IllegalArgumentException("secret is required"));
    issuer = Optional.ofNullable(query.get("issuer"))
      .or(() -> Optional.of(label)
        .map(l -> l.split(":"))
        .filter(l -> l.length > 1)
        .map(l -> l[1]))
      .orElseThrow(() -> new IllegalArgumentException("issuer is required"));
    algorithm = Optional.ofNullable(query.get("algorithm"))
      .map(x -> "Hmac" + x)
      .map(Algorithm::valueOf)
      .orElse(HmacSHA1);
    digits = Optional.ofNullable(query.get("digits"))
      .map(Integer::valueOf)
      .orElse(6);
    counter = Optional.ofNullable(query.get("counter"))
      .map(Integer::valueOf)
      .orElse(0);
    period = Optional.ofNullable(query.get("period"))
      .map(Integer::valueOf)
      .orElse(30);
  }

  @Override
  public String toString() {
    return "Parameters{" +
      "type=" + type +
      ", label='" + label + '\'' +
      ", secret=" + secret +
      ", issuer='" + issuer + '\'' +
      ", algorithm=" + algorithm +
      ", digits=" + digits +
      ", counter=" + counter +
      ", period=" + period +
      '}';
  }
}
