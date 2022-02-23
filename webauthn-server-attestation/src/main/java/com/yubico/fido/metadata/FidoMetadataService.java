// Copyright (c) 2015-2021, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.fido.metadata;

import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.RelyingParty.RelyingPartyBuilder;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility for filtering and querying <a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">Fido
 * Metadata Service BLOB entries</a>.
 *
 * <p>This class implements {@link AttestationTrustSource}, so it can be configured as the {@link
 * RelyingPartyBuilder#attestationTrustSource(AttestationTrustSource) attestationTrustSource}
 * setting in {@link RelyingParty}.
 *
 * <p>The metadata service may be configured with a {@link
 * FidoMetadataServiceBuilder#filter(Predicate) filter} to select trusted authenticators. This
 * filter is executed when the {@link FidoMetadataService} instance is constructed. Any metadata
 * entry that matches the filter will be considered trusted.
 *
 * <p>Use the {@link #builder() builder} to configure settings, then use the {@link
 * #findEntry(AAGUID)} and/or {@link #findEntry(List)} methods to retrieve metadata entries.
 */
@Slf4j
public final class FidoMetadataService implements AttestationTrustSource {

  private final List<MetadataBLOBPayloadEntry> filteredEntries;
  private final CertStore certStore;

  private FidoMetadataService(
      @NonNull MetadataBLOBPayload blob,
      @NonNull Predicate<MetadataBLOBPayloadEntry> filter,
      CertStore certStore) {
    this.filteredEntries =
        Collections.unmodifiableList(
            blob.getEntries().stream().filter(filter).collect(Collectors.toList()));
    this.certStore = certStore;
  }

  public static FidoMetadataServiceBuilder.Step1 builder() {
    return new FidoMetadataServiceBuilder.Step1();
  }

  @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
  public static class FidoMetadataServiceBuilder {
    private final FidoMetadataDownloader downloader;
    private final MetadataBLOBPayload blob;

    private Predicate<MetadataBLOBPayloadEntry> filter = Filters.notRevoked();
    private CertStore certStore = null;

    public static class Step1 {
      /**
       * Use the given <code>downloader</code> to retrieve the data source.
       *
       * <p>The <code>downloader</code>'s {@link FidoMetadataDownloader#loadBlob()} method will be
       * called in the {@link #build()} method to construct the {@link FidoMetadataService}
       * instance. Once the {@link FidoMetadataService} is constructed, the <code>downloader</code>
       * will not be used again.
       */
      public FidoMetadataServiceBuilder useDownloader(@NonNull FidoMetadataDownloader downloader) {
        return new FidoMetadataServiceBuilder(downloader, null);
      }

      /** Use the given <code>blob</code> as the data source. */
      public FidoMetadataServiceBuilder useBlob(@NonNull MetadataBLOBPayload blob) {
        return new FidoMetadataServiceBuilder(null, blob);
      }
    }

    /**
     * Set a filter for which metadata entries to include in the data source.
     *
     * <p>The default is {@link Filters#notRevoked() Filters.notRevoked()}. Setting a different
     * filter overrides this default; to preserve the "not revoked" condition in addition to the new
     * filter, you must explicitly include the condition in the few filter. For example, by using
     * {@link Filters#allOf(Predicate[]) Filters.allOf(Predicate...)}.
     *
     * @param filter a {@link Predicate} which returns <code>true</code> for metadata entries to
     *     include in the data source.
     */
    public FidoMetadataServiceBuilder filter(@NonNull Predicate<MetadataBLOBPayloadEntry> filter) {
      this.filter = filter;
      return this;
    }

    /**
     * Set a {@link CertStore} of additional CRLs and/or intermediate certificates to use while
     * validating attestation certificate paths.
     *
     * <p>This setting is most likely useful for tests.
     *
     * @param certStore a {@link CertStore} of additional CRLs and/or intermediate certificates to
     *     use while validating attestation certificate paths.
     */
    public FidoMetadataServiceBuilder certStore(@NonNull CertStore certStore) {
      this.certStore = certStore;
      return this;
    }

    public FidoMetadataService build()
        throws CertPathValidatorException, InvalidAlgorithmParameterException, Base64UrlException,
            DigestException, FidoMetadataDownloaderException, CertificateException,
            UnexpectedLegalHeader, IOException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException {
      if (downloader == null && blob != null) {
        return new FidoMetadataService(blob, filter, certStore);
      } else if (downloader != null && blob == null) {
        return new FidoMetadataService(downloader.loadBlob().getPayload(), filter, certStore);
      } else {
        throw new IllegalStateException(
            "Either downloader or blob must be provided, none was. This should not be possible, please file a bug report.");
      }
    }
  }

  /**
   * Preconfigured filters and utilities for combining filters. See the {@link
   * FidoMetadataServiceBuilder#filter(Predicate) filter} setting.
   *
   * @see FidoMetadataServiceBuilder#filter(Predicate)
   */
  public static class Filters {
    /**
     * Combine a set of filters into a filter that requires metadata entries to satisfy ALL of those
     * filters.
     *
     * <p>If <code>filters</code> is empty, then all metadata entries will satisfy the resulting
     * filter.
     *
     * @param filters A set of filters.
     * @return A filter which only includes metadata entries that satisfy ALL of the given <code>
     *     filters</code>.
     */
    public static Predicate<MetadataBLOBPayloadEntry> allOf(
        Predicate<MetadataBLOBPayloadEntry>... filters) {
      return (entry) -> Stream.of(filters).allMatch(filter -> filter.test(entry));
    }

    /**
     * Include any metadata entry whose {@link MetadataBLOBPayloadEntry#getStatusReports()
     * statusReports} array contains no entry with {@link AuthenticatorStatus#REVOKED REVOKED}
     * status.
     *
     * @see AuthenticatorStatus#REVOKED
     */
    public static Predicate<MetadataBLOBPayloadEntry> notRevoked() {
      return (entry) ->
          entry.getStatusReports().stream()
              .noneMatch(
                  statusReport -> AuthenticatorStatus.REVOKED.equals(statusReport.getStatus()));
    }
  }

  Stream<MetadataBLOBPayloadEntry> getFilteredEntries() {
    return filteredEntries.stream();
  }

  public Optional<MetadataBLOBPayloadEntry> findEntry(AAGUID aaguid) {
    if (aaguid.isZero()) {
      log.debug("findEntry(aaguid = {}) => ignoring zero AAGUID", aaguid);
      return Optional.empty();
    } else {
      final Optional<MetadataBLOBPayloadEntry> result =
          getFilteredEntries()
              .filter(entry -> aaguid.equals(entry.getAaguid().orElse(null)))
              .findAny();
      log.debug("findEntry(aaguid = {}) => {}", aaguid, result.isPresent() ? "found" : "not found");
      return result;
    }
  }

  /**
   * @param attestationCertificateChain
   * @return
   */
  public Optional<MetadataBLOBPayloadEntry> findEntry(
      List<X509Certificate> attestationCertificateChain) {
    for (X509Certificate cert : attestationCertificateChain) {
      final String subjectKeyIdentifierHex;
      try {
        subjectKeyIdentifierHex =
            new ByteArray(CertificateParser.computeSubjectKeyIdentifier(cert)).getHex();
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("SHA-1 hash algorithm is not available in JCA context.", e);
      }

      final Optional<MetadataBLOBPayloadEntry> certSubjectKeyIdentifierMatch =
          getFilteredEntries()
              .filter(
                  entry ->
                      entry.getAttestationCertificateKeyIdentifiers().stream()
                              .anyMatch(subjectKeyIdentifierHex::equals)
                          || entry
                              .getMetadataStatement()
                              .map(
                                  stmt ->
                                      stmt.getAttestationCertificateKeyIdentifiers().stream()
                                          .anyMatch(subjectKeyIdentifierHex::equals))
                              .orElse(false))
              .findAny();

      if (certSubjectKeyIdentifierMatch.isPresent()) {
        log.debug("findEntry(certKeyIdentifier = {}) => found", subjectKeyIdentifierHex);
        return certSubjectKeyIdentifierMatch;
      } else {
        log.debug("findEntry(certKeyIdentifier = {}) => not found", subjectKeyIdentifierHex);
      }
    }

    return Optional.empty();
  }

  @Override
  public Set<X509Certificate> findTrustRoots(ByteArray aaguid) {
    return findEntry(new AAGUID(aaguid))
        .flatMap(MetadataBLOBPayloadEntry::getMetadataStatement)
        .map(MetadataStatement::getAttestationRootCertificates)
        .orElseGet(Collections::emptySet);
  }

  @Override
  public Set<X509Certificate> findTrustRoots(List<X509Certificate> attestationCertificateChain) {
    return findEntry(attestationCertificateChain)
        .flatMap(MetadataBLOBPayloadEntry::getMetadataStatement)
        .map(MetadataStatement::getAttestationRootCertificates)
        .orElseGet(Collections::emptySet);
  }

  @Override
  public Optional<CertStore> getCertStore(List<X509Certificate> attestationCertificateChain) {
    return Optional.ofNullable(certStore);
  }
}
