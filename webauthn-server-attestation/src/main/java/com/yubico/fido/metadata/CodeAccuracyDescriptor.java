package com.yubico.fido.metadata;

import java.util.Optional;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * The CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user
 * verification methods.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary">FIDO
 *     Metadata Statement §3.2. CodeAccuracyDescriptor dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class CodeAccuracyDescriptor {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.2. CodeAccuracyDescriptor dictionary</a>
   */
  int base;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.2. CodeAccuracyDescriptor dictionary</a>
   */
  int minLength;

  Integer maxRetries;
  Integer blockSlowdown;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.2. CodeAccuracyDescriptor dictionary</a>
   */
  public Optional<Integer> getMaxRetries() {
    return Optional.ofNullable(maxRetries);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.2. CodeAccuracyDescriptor dictionary</a>
   */
  public Optional<Integer> getBlockSlowdown() {
    return Optional.ofNullable(blockSlowdown);
  }
}
