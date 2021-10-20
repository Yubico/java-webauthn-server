package com.yubico.fido.metadata;

import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.ByteArray;
import java.net.URL;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * An element of {@link MetadataBLOBPayload#getEntries() entries} in a {@link MetadataBLOBPayload}.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
 *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class MetadataBLOBPayloadEntry {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  AAID aaid;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  AAGUID aaguid;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  Set<String> attestationCertificateKeyIdentifiers;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  MetadataStatement metadataStatement;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  List<BiometricStatusReport> biometricStatusReports;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  @NonNull List<StatusReport> statusReports;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  @NonNull LocalDate timeOfLastStatusChange;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  URL rogueListURL;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  ByteArray rogueListHash;

  private MetadataBLOBPayloadEntry(
      AAID aaid,
      AAGUID aaguid,
      Set<String> attestationCertificateKeyIdentifiers,
      MetadataStatement metadataStatement,
      List<BiometricStatusReport> biometricStatusReports,
      @NonNull List<StatusReport> statusReports,
      @NonNull LocalDate timeOfLastStatusChange,
      URL rogueListURL,
      ByteArray rogueListHash) {
    this.aaid = aaid;
    this.aaguid = aaguid;
    this.attestationCertificateKeyIdentifiers =
        CollectionUtil.immutableSetOrEmpty(attestationCertificateKeyIdentifiers);
    this.metadataStatement = metadataStatement;
    this.biometricStatusReports = CollectionUtil.immutableListOrEmpty(biometricStatusReports);
    this.statusReports = CollectionUtil.immutableListOrEmpty(statusReports);
    this.timeOfLastStatusChange = timeOfLastStatusChange;
    this.rogueListURL = rogueListURL;
    this.rogueListHash = rogueListHash;
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  public Optional<AAID> getAaid() {
    return Optional.ofNullable(this.aaid);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  public Optional<AAGUID> getAaguid() {
    return Optional.ofNullable(this.aaguid);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  public Optional<MetadataStatement> getMetadataStatement() {
    return Optional.ofNullable(this.metadataStatement);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  public Optional<LocalDate> getTimeOfLastStatusChange() {
    return Optional.of(this.timeOfLastStatusChange);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  public Optional<URL> getRogueListURL() {
    return Optional.ofNullable(this.rogueListURL);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">FIDO
   *     Metadata Service §3.1.1. Metadata BLOB Payload Entry dictionary</a>
   */
  public Optional<ByteArray> getRogueListHash() {
    return Optional.ofNullable(this.rogueListHash);
  }
}
