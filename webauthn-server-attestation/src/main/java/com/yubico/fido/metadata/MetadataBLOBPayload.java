package com.yubico.fido.metadata;

import java.time.LocalDate;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * The metadata BLOB is a JSON Web Token (see [<a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-jwt">JWT</a>]
 * and [<a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biblio-jws">JWS</a>]).
 *
 * <p>This type represents the contents of the JWT payload.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">FIDO
 *     Metadata Service §3.1.7. Metadata BLOB</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary">FIDO
 *     Metadata Service §3.1.6. Metadata BLOB Payload dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class MetadataBLOBPayload {

  /**
   * The legalHeader, which MUST be in each BLOB, is an indication of the acceptance of the relevant
   * legal agreement for using the MDS.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary">FIDO
   *     Metadata Service §3.1.6. Metadata BLOB Payload dictionary</a>
   */
  String legalHeader;

  /**
   * The serial number of this Metadata BLOB Payload. Serial numbers MUST be consecutive and
   * strictly monotonic, i.e. the successor BLOB will have a <code>no</code> value exactly
   * incremented by one.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary">FIDO
   *     Metadata Service §3.1.6. Metadata BLOB Payload dictionary</a>
   */
  int no;

  /**
   * ISO-8601 formatted date when the next update will be provided at latest.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary">FIDO
   *     Metadata Service §3.1.6. Metadata BLOB Payload dictionary</a>
   */
  @NonNull LocalDate nextUpdate;

  /**
   * Zero or more {@link MetadataBLOBPayloadEntry} objects.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary">FIDO
   *     Metadata Service §3.1.6. Metadata BLOB Payload dictionary</a>
   */
  @NonNull Set<MetadataBLOBPayloadEntry> entries;
}
