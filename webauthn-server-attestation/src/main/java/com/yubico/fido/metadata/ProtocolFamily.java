package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Enumeration of valid values for {@link MetadataStatement#getProtocolFamily()}.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-protocolfamily">FIDO
 *     Metadata Statement §4. Metadata Keys</a>
 */
public enum ProtocolFamily {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-protocolfamily">FIDO
   *     Metadata Statement §4. Metadata Keys</a>
   */
  UAF("uaf"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-protocolfamily">FIDO
   *     Metadata Statement §4. Metadata Keys</a>
   */
  U2F("u2f"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-protocolfamily">FIDO
   *     Metadata Statement §4. Metadata Keys</a>
   */
  FIDO2("fido2");

  @JsonValue private final String value;

  ProtocolFamily(String value) {
    this.value = value;
  }
}
