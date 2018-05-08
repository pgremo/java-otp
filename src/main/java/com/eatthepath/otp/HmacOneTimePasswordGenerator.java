/* Copyright (c) 2016 Jon Chambers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. */

package com.eatthepath.otp;

import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static com.eatthepath.otp.Algorithm.HmacSHA1;

/**
 * <p>Generates HMAC-based one-time passwords (HOTP) as specified in
 * <a href="https://tools.ietf.org/html/rfc4226">RFC&nbsp;4226</a>.</p>
 *
 * <p>{@code HmacOneTimePasswordGenerator} instances are thread-safe and may be shared and re-used across multiple
 * threads.</p>
 *
 * @author <a href="https://github.com/jchambers">Jon Chambers</a>
 */
public class HmacOneTimePasswordGenerator {
  private final Algorithm algorithm;
  private final int passwordLength;
  private final int modDivisor;

  /**
   * The default length, in decimal digits, for one-time passwords.
   */
  public static final int DEFAULT_PASSWORD_LENGTH = 6;

  public HmacOneTimePasswordGenerator() throws NoSuchAlgorithmException {
    this(DEFAULT_PASSWORD_LENGTH);
  }

  public HmacOneTimePasswordGenerator(final int passwordLength) throws NoSuchAlgorithmException {
    this(passwordLength, HmacSHA1);
  }

  protected HmacOneTimePasswordGenerator(final int passwordLength, final Algorithm algorithm) throws NoSuchAlgorithmException {
    if (passwordLength < 6 || passwordLength > 8)
      throw new IllegalArgumentException("Password length must be between 6 and 8 digits.");
    this.modDivisor = (int) Math.pow(10, passwordLength);
    this.passwordLength = passwordLength;
    // Our purpose here is just to throw an exception immediately if the algorithm is bogus.
    Mac.getInstance(algorithm.toString());
    this.algorithm = algorithm;
  }

  /**
   * Generates a one-time password using the given key and counter value.
   *
   * @param key     a secret key to be used to generate the password
   * @param counter the counter value to be used to generate the password
   * @return an integer representation of a one-time password; callers will need to format the password for display
   * on their own
   * @throws InvalidKeyException if the given key is inappropriate for initializing the {@link Mac} for this generator
   */
  public int generateOneTimePassword(final Key key, final long counter) throws InvalidKeyException {
    final Mac mac;

    try {
      mac = Mac.getInstance(this.algorithm.toString());
      mac.init(key);
    } catch (final NoSuchAlgorithmException e) {
      // This should never happen since we verify that the algorithm is legit in the constructor.
      throw new RuntimeException(e);
    }

    final var buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.putLong(0, counter);
    final var hmac = mac.doFinal(buffer.array());
    final var offset = hmac[hmac.length - 1] & 0x0f;

    buffer.put(hmac, offset, Integer.BYTES);

    final var hotp = buffer.getInt(0) & Integer.MAX_VALUE;

    return hotp % this.modDivisor;
  }

  /**
   * Returns the length, in decimal digits, of passwords produced by this generator.
   *
   * @return the length, in decimal digits, of passwords produced by this generator
   */
  public int getPasswordLength() {
    return this.passwordLength;
  }

  /**
   * Returns the name of the HMAC algorithm used by this generator.
   *
   * @return the name of the HMAC algorithm used by this generator
   */
  public Algorithm getAlgorithm() {
    return this.algorithm;
  }
}
