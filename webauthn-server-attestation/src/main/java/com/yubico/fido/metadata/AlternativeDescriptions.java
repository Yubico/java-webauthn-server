package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Map;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Value;

/**
 * See:
 * https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#alternativedescriptions-dictionary
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#alternativedescriptions-dictionary">FIDO
 *     Metadata Statement §3.11. AlternativeDescriptions dictionary</a>
 */
@Value
@AllArgsConstructor(onConstructor_ = {@JsonCreator})
public class AlternativeDescriptions {

  @JsonValue
  @Getter(AccessLevel.NONE)
  Map<String, String> values;

  /**
   * Get a map entry in accordance with the rules defined in <a
   * href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#alternativedescriptions-dictionary">AlternativeDescriptions
   * dictionary</a>.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#alternativedescriptions-dictionary">AlternativeDescriptions
   *     dictionary</a>.
   */
  public Optional<String> get(String languageCode) {
    if (values.containsKey(languageCode)) {
      return Optional.of(values.get(languageCode));
    } else {
      final String[] splits = languageCode.split("-");
      if (splits.length > 1 && values.containsKey(splits[0])) {
        return Optional.of(values.get(splits[0]));
      } else {
        return Optional.empty();
      }
    }
  }
}
