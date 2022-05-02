package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.regex.Pattern;
import lombok.Value;

/**
 * Each UAF authenticator MUST have an AAID to identify UAF enabled authenticator models globally.
 * The AAID MUST uniquely identify a specific authenticator model within the range of all
 * UAF-enabled authenticator models made by all authenticator vendors, where authenticators of a
 * specific model must share identical security characteristics within the model (see Security
 * Considerations).
 *
 * <p>The AAID is a string with format <code>"V#M"</code>, where
 *
 * <ul>
 *   <li><code>#</code> is a separator
 *   <li><code>V</code> indicates the authenticator Vendor Code. This code consists of 4 hexadecimal
 *       digits.
 *   <li><code>M</code> indicates the authenticator Model Code. This code consists of 4 hexadecimal
 *       digits.
 * </ul>
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef">FIDO
 *     UAF Protocol Specification §3.1.4 Authenticator Attestation ID (AAID) typedef</a>
 */
@Value
public class AAID {

  private static final Pattern AAID_PATTERN = Pattern.compile("^[0-9a-fA-F]{4}#[0-9a-fA-F]{4}$");

  /**
   * The underlying string value of this AAID.
   *
   * <p>The AAID is a string with format <code>"V#M"</code>, where
   *
   * <ul>
   *   <li><code>#</code> is a separator
   *   <li><code>V</code> indicates the authenticator Vendor Code. This code consists of 4
   *       hexadecimal digits.
   *   <li><code>M</code> indicates the authenticator Model Code. This code consists of 4
   *       hexadecimal digits.
   * </ul>
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef">Authenticator
   *     Attestation ID (AAID) typedef</a>
   */
  @JsonValue String value;

  /**
   * Construct an {@link AAID} from its String representation.
   *
   * <p>This is the inverse of {@link #getValue()}.
   *
   * @param value a {@link String} conforming to the rules specified in the {@link AAID} type.
   */
  @JsonCreator
  public AAID(String value) {
    this.value = validate(value);
  }

  private String validate(String value) {
    if (AAID_PATTERN.matcher(value).matches()) {
      return value;
    } else {
      throw new IllegalArgumentException(
          String.format("Value does not satisfy AAID format: %s", value));
    }
  }
}
