package com.yubico.fido.metadata;

import lombok.Value;

/**
 * The header and payload of a FIDO Metadata Service BLOB.
 *
 * <p>This does not include the JWT signature.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">FIDO
 *     Metadata Service §3.1.7. Metadata BLOB</a>
 */
@Value
public class MetadataBLOB {

  /**
   * The JWT header of the FIDO Metadata Service BLOB.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">FIDO
   *     Metadata Service §3.1.7. Metadata BLOB</a>
   */
  MetadataBLOBHeader header;

  /**
   * The payload of the Metadata Service BLOB.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">FIDO
   *     Metadata Service §3.1.7. Metadata BLOB</a>
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary">FIDO
   *     Metadata Service §3.1.6. Metadata BLOB Payload dictionary</a>
   */
  MetadataBLOBPayload payload;
}
