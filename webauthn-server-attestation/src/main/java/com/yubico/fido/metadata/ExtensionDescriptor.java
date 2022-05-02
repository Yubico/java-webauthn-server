package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * This descriptor contains an extension supported by the authenticator.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary">FIDO
 *     Metadata Statement §3.10. ExtensionDescriptor dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class ExtensionDescriptor {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary">FIDO
   *     Metadata Statement §3.10. ExtensionDescriptor dictionary</a>
   */
  @NonNull String id;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary">FIDO
   *     Metadata Statement §3.10. ExtensionDescriptor dictionary</a>
   */
  Integer tag;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary">FIDO
   *     Metadata Statement §3.10. ExtensionDescriptor dictionary</a>
   */
  String data;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary">FIDO
   *     Metadata Statement §3.10. ExtensionDescriptor dictionary</a>
   */
  @JsonProperty("fail_if_unknown")
  boolean failIfUnknown;
}
