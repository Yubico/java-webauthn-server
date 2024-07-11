package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.data.ByteArray;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.ToString;
import lombok.Value;

/**
 * Some authenticators have an AAGUID, which is a 128-bit identifier that indicates the type (e.g.
 * make and model) of the authenticator. The AAGUID MUST be chosen by the manufacturer to be
 * identical across all substantially identical authenticators made by that manufacturer, and
 * different (with probability 1-2-128 or greater) from the AAGUIDs of all other types of
 * authenticators.
 *
 * <p>The AAGUID is represented as a string (e.g. "7a98c250-6808-11cf-b73b-00aa00b677a7") consisting
 * of 5 hex strings separated by a dash ("-"), see [RFC4122].
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#typedefdef-aaguid">FIDO
 *     Metadata Statement §3.1. Authenticator Attestation GUID (AAGUID) typedef</a>
 * @see <a href="https://tools.ietf.org/html/rfc4122">RFC 4122: A Universally Unique IDentifier
 *     (UUID) URN Namespace</a>
 */
@Value
@Getter(AccessLevel.NONE)
@ToString(includeFieldNames = false, onlyExplicitlyIncluded = true)
public class AAGUID {

  private static final Pattern AAGUID_PATTERN =
      Pattern.compile(
          "^([0-9a-fA-F]{8})-?([0-9a-fA-F]{4})-?([0-9a-fA-F]{4})-?([0-9a-fA-F]{4})-?([0-9a-fA-F]{12})$");

  private static final ByteArray ZERO =
      new ByteArray(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

  ByteArray value;

  /**
   * Construct an AAGUID from its raw binary representation.
   *
   * <p>This is the inverse of {@link #asBytes()}.
   *
   * @param value a {@link ByteArray} of length exactly 16.
   */
  public AAGUID(ByteArray value) {
    ExceptionUtil.assertTrue(
        value.size() == 16,
        "AAGUID as bytes must be exactly 16 bytes long, was %d: %s",
        value.size(),
        value);
    this.value = value;
  }

  /**
   * The 16-byte binary representation of this AAGUID, for example <code>
   * 7a98c250680811cfb73b00aa00b677a7</code> when hex-encoded.
   *
   * <p>This is the inverse of {@link #AAGUID(ByteArray)}.
   */
  public ByteArray asBytes() {
    return value;
  }

  /**
   * The 32-character hexadecimal representation of this AAGUID, for example <code>
   * "7a98c250680811cfb73b00aa00b677a7"</code>.
   */
  public String asHexString() {
    return value.getHex();
  }

  /**
   * The 36-character string representation of this AAGUID, for example <code>
   * "7a98c250-6808-11cf-b73b-00aa00b677a7"</code>.
   */
  @JsonValue
  @ToString.Include
  public String asGuidString() {
    final String hex = value.getHex();
    return String.format(
        "%s-%s-%s-%s-%s",
        hex.substring(0, 8),
        hex.substring(8, 8 + 4),
        hex.substring(8 + 4, 8 + 4 + 4),
        hex.substring(8 + 4 + 4, 8 + 4 + 4 + 4),
        hex.substring(8 + 4 + 4 + 4, 8 + 4 + 4 + 4 + 12));
  }

  /**
   * <code>true</code> if and only if this {@link AAGUID} consists of all zeroes. This typically
   * indicates that an authenticator has no AAGUID, or that the AAGUID has been redacted.
   */
  public boolean isZero() {
    return ZERO.equals(value);
  }

  private static ByteArray parse(String value) {
    Matcher matcher = AAGUID_PATTERN.matcher(value);
    if (matcher.find()) {
      try {
        return new ByteArray(
            BinaryUtil.concat(
                BinaryUtil.fromHex(matcher.group(1)),
                BinaryUtil.fromHex(matcher.group(2)),
                BinaryUtil.fromHex(matcher.group(3)),
                BinaryUtil.fromHex(matcher.group(4)),
                BinaryUtil.fromHex(matcher.group(5))));
      } catch (Exception e) {
        throw new RuntimeException(
            "This exception should be impossible, please file a bug report.", e);
      }
    } else {
      throw new IllegalArgumentException("Value does not match AAGUID pattern: " + value);
    }
  }

  @JsonCreator
  private static AAGUID fromString(String aaguid) {
    return new AAGUID(parse(aaguid));
  }
}
