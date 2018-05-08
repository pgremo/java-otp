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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static com.eatthepath.otp.Algorithm.HmacSHA256;
import static java.nio.charset.StandardCharsets.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HmacOneTimePasswordGeneratorTest {

  @Test
  void testHmacOneTimePasswordGeneratorWithShortPasswordLength() {
    assertThrows(IllegalArgumentException.class, () -> new HmacOneTimePasswordGenerator(5));
  }

  @Test
  void testHmacOneTimePasswordGeneratorWithLongPasswordLength() {
    assertThrows(IllegalArgumentException.class, () -> new HmacOneTimePasswordGenerator(9));
  }

  @Test
  void testGetPasswordLength() throws NoSuchAlgorithmException {
    assertEquals(7, new HmacOneTimePasswordGenerator(7).getPasswordLength());
  }

  @Test
  void testGetAlgorithm() throws NoSuchAlgorithmException {
    assertEquals(HmacSHA256, new HmacOneTimePasswordGenerator(6, HmacSHA256).getAlgorithm());
  }

  private final Key key = new SecretKeySpec("12345678901234567890".getBytes(US_ASCII), "RAW");
  /**
   * Tests generation of one-time passwords using the test vectors from
   * <a href="https://tools.ietf.org/html/rfc4226#appendix-D">RFC&nbsp;4226, Appendix D</a>.
   */
  @ParameterizedTest
  @CsvSource({
    "0, 755224",
    "1, 287082",
    "2, 359152",
    "3, 969429",
    "4, 338314",
    "5, 254676",
    "6, 287922",
    "7, 162583",
    "8, 399871",
    "9, 520489"})
  void testGenerateOneTimePassword(final int counter, final int expectedOneTimePassword) throws Exception {
    assertEquals(expectedOneTimePassword, new HmacOneTimePasswordGenerator().generateOneTimePassword(key, counter));
  }

}
