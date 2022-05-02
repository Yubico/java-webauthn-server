package com.yubico.fido.metadata;

import java.util.Optional;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * The {@link PatternAccuracyDescriptor} describes relevant accuracy/complexity aspects in the case
 * that a pattern is used as the user verification method.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary">FIDO
 *     Metadata Statement §3.4. PatternAccuracyDescriptor dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class PatternAccuracyDescriptor {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.4. PatternAccuracyDescriptor dictionary</a>
   */
  long minComplexity;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.4. PatternAccuracyDescriptor dictionary</a>
   */
  Integer maxRetries;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.4. PatternAccuracyDescriptor dictionary</a>
   */
  Integer blockSlowdown;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.4. PatternAccuracyDescriptor dictionary</a>
   */
  public Optional<Integer> getMaxRetries() {
    return Optional.ofNullable(maxRetries);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.4. PatternAccuracyDescriptor dictionary</a>
   */
  public Optional<Integer> getBlockSlowdown() {
    return Optional.ofNullable(blockSlowdown);
  }
}
