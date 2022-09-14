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

import com.yubico.fido.metadata.FidoMetadataService.Filters.AuthenticatorToBeFiltered;
import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.RegistrationResult;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility for filtering and querying <a
 * href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary">Fido
 * Metadata Service BLOB entries</a>.
 *
 * <p>This class implements {@link AttestationTrustSource}, so it can be configured as the {@link
 * RelyingPartyBuilder#attestationTrustSource(AttestationTrustSource) attestationTrustSource}
 * setting in {@link RelyingParty}. This implementation always sets {@link
 * com.yubico.webauthn.attestation.AttestationTrustSource.TrustRootsResult.TrustRootsResultBuilder#enableRevocationChecking(boolean)
 * enableRevocationChecking(false)}, because the FIDO MDS has its own revocation procedures and not
 * all attestation certificates provide CRLs; and always sets {@link
 * com.yubico.webauthn.attestation.AttestationTrustSource.TrustRootsResult.TrustRootsResultBuilder#policyTreeValidator(Predicate)
 * policyTreeValidator} to accept any policy tree, because a Windows Hello attestation certificate
 * is known to include a critical certificate policies extension.
 *
 * <p>The metadata service may be configured with two stages of filters to select trusted
 * authenticators. The first stage is the {@link FidoMetadataServiceBuilder#prefilter(Predicate)
 * prefilter} setting, which is executed once when the {@link FidoMetadataService} instance is
 * constructed. The second stage is the {@link FidoMetadataServiceBuilder#filter(Predicate) filter}
 * setting, which is executed whenever metadata or trust roots are to be looked up for a given
 * authenticator. Any metadata entry that satisfies both filters will be considered trusted.
 *
 * <p>Use the {@link #builder() builder} to configure settings, then use the {@link
 * #findEntries(List, AAGUID)} method or its overloads to retrieve metadata entries.
 */
@Slf4j
public final class FidoMetadataService implements AttestationTrustSource {

  private final HashMap<String, HashSet<MetadataBLOBPayloadEntry>>
      prefilteredEntriesByCertificateKeyIdentifier;
  private final HashMap<AAGUID, HashSet<MetadataBLOBPayloadEntry>> prefilteredEntriesByAaguid;
  private final HashSet<MetadataBLOBPayloadEntry> prefilteredUnindexedEntries;

  private final Predicate<AuthenticatorToBeFiltered> filter;
  private final CertStore certStore;

  private FidoMetadataService(
      @NonNull MetadataBLOBPayload blob,
      @NonNull Predicate<MetadataBLOBPayloadEntry> prefilter,
      @NonNull Predicate<AuthenticatorToBeFiltered> filter,
      CertStore certStore) {
    final List<MetadataBLOBPayloadEntry> prefilteredEntries =
        blob.getEntries().stream()
            .filter(FidoMetadataService::ignoreInvalidUpdateAvailableAuthenticatorVersion)
            .filter(prefilter)
            .collect(Collectors.toList());

    this.prefilteredEntriesByCertificateKeyIdentifier = buildCkiMap(prefilteredEntries);
    this.prefilteredEntriesByAaguid = buildAaguidMap(prefilteredEntries);

    this.prefilteredUnindexedEntries = new HashSet<>(prefilteredEntries);
    for (HashSet<MetadataBLOBPayloadEntry> byAaguid : prefilteredEntriesByAaguid.values()) {
      prefilteredUnindexedEntries.removeAll(byAaguid);
    }
    for (HashSet<MetadataBLOBPayloadEntry> byCski :
        prefilteredEntriesByCertificateKeyIdentifier.values()) {
      prefilteredUnindexedEntries.removeAll(byCski);
    }

    this.filter = filter;
    this.certStore = certStore;
  }

  private static boolean ignoreInvalidUpdateAvailableAuthenticatorVersion(
      MetadataBLOBPayloadEntry metadataBLOBPayloadEntry) {
    return metadataBLOBPayloadEntry
        .getMetadataStatement()
        .map(MetadataStatement::getAuthenticatorVersion)
        .map(
            authenticatorVersion ->
                metadataBLOBPayloadEntry.getStatusReports().stream()
                    .filter(
                        statusReport ->
                            AuthenticatorStatus.UPDATE_AVAILABLE.equals(statusReport.getStatus()))
                    .noneMatch(
                        statusReport ->
                            statusReport
                                .getAuthenticatorVersion()
                                .map(av -> av > authenticatorVersion)
                                .orElse(false)))
        .orElse(true);
  }

  private static HashMap<String, HashSet<MetadataBLOBPayloadEntry>> buildCkiMap(
      @NonNull List<MetadataBLOBPayloadEntry> entries) {

    return entries.stream()
        .collect(
            HashMap::new,
            (result, metadataBLOBPayloadEntry) -> {
              for (String acki :
                  metadataBLOBPayloadEntry.getAttestationCertificateKeyIdentifiers()) {
                result.computeIfAbsent(acki, o -> new HashSet<>()).add(metadataBLOBPayloadEntry);
              }
              for (String acki :
                  metadataBLOBPayloadEntry
                      .getMetadataStatement()
                      .map(MetadataStatement::getAttestationCertificateKeyIdentifiers)
                      .orElseGet(Collections::emptySet)) {
                result.computeIfAbsent(acki, o -> new HashSet<>()).add(metadataBLOBPayloadEntry);
              }
            },
            (mapA, mapB) -> {
              for (Map.Entry<String, HashSet<MetadataBLOBPayloadEntry>> e : mapB.entrySet()) {
                mapA.merge(
                    e.getKey(),
                    e.getValue(),
                    (entriesA, entriesB) -> {
                      entriesA.addAll(entriesB);
                      return entriesA;
                    });
              }
            });
  }

  private static HashMap<AAGUID, HashSet<MetadataBLOBPayloadEntry>> buildAaguidMap(
      @NonNull List<MetadataBLOBPayloadEntry> entries) {

    return entries.stream()
        .collect(
            HashMap::new,
            (result, metadataBLOBPayloadEntry) -> {
              final Consumer<AAGUID> appendToAaguidEntry =
                  aaguid ->
                      result
                          .computeIfAbsent(aaguid, o -> new HashSet<>())
                          .add(metadataBLOBPayloadEntry);
              metadataBLOBPayloadEntry
                  .getAaguid()
                  .filter(aaguid -> !aaguid.isZero())
                  .ifPresent(appendToAaguidEntry);
              metadataBLOBPayloadEntry
                  .getMetadataStatement()
                  .flatMap(MetadataStatement::getAaguid)
                  .filter(aaguid -> !aaguid.isZero())
                  .ifPresent(appendToAaguidEntry);
            },
            (mapA, mapB) -> {
              for (Map.Entry<AAGUID, HashSet<MetadataBLOBPayloadEntry>> e : mapB.entrySet()) {
                mapA.merge(
                    e.getKey(),
                    e.getValue(),
                    (entriesA, entriesB) -> {
                      entriesA.addAll(entriesB);
                      return entriesA;
                    });
              }
            });
  }

  public static FidoMetadataServiceBuilder.Step1 builder() {
    return new FidoMetadataServiceBuilder.Step1();
  }

  @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
  public static class FidoMetadataServiceBuilder {
    @NonNull private final MetadataBLOBPayload blob;

    private Predicate<MetadataBLOBPayloadEntry> prefilter = Filters.notRevoked();
    private Predicate<AuthenticatorToBeFiltered> filter = Filters.noAttestationKeyCompromise();
    private CertStore certStore = null;

    public static class Step1 {
      /**
       * Use payload of the given <code>blob</code> as the data source.
       *
       * <p>The {@link FidoMetadataDownloader#loadCachedBlob()} method returns a value suitable for
       * use here.
       *
       * <p>This is an alias of <code>useBlob(blob.getPayload()</code>.
       *
       * @see FidoMetadataDownloader#loadCachedBlob()
       * @see #useBlob(MetadataBLOBPayload)
       */
      public FidoMetadataServiceBuilder useBlob(@NonNull MetadataBLOB blob) {
        return useBlob(blob.getPayload());
      }

      /**
       * Use the given <code>blobPayload</code> as the data source.
       *
       * <p>The {@link FidoMetadataDownloader#loadCachedBlob()} method returns a value whose {@link
       * MetadataBLOB#getPayload() .getPayload()} result is suitable for use here.
       *
       * @see FidoMetadataDownloader#loadCachedBlob()
       * @see #useBlob(MetadataBLOB)
       */
      public FidoMetadataServiceBuilder useBlob(@NonNull MetadataBLOBPayload blobPayload) {
        return new FidoMetadataServiceBuilder(blobPayload);
      }
    }

    /**
     * Set a first-stage filter for which metadata entries to include in the data source.
     *
     * <p>This prefilter is executed once for each metadata entry during initial construction of a
     * {@link FidoMetadataService} instance.
     *
     * <p>The default is {@link Filters#notRevoked() Filters.notRevoked()}. Setting a different
     * filter overrides this default; to preserve the "not revoked" condition in addition to the new
     * filter, you must explicitly include the condition in the few filter. For example, by using
     * {@link Filters#allOf(Predicate[]) Filters.allOf(Predicate...)}.
     *
     * @param prefilter a {@link Predicate} which returns <code>true</code> for metadata entries to
     *     include in the data source.
     * @see #filter(Predicate)
     * @see Filters#allOf(Predicate[])
     */
    public FidoMetadataServiceBuilder prefilter(
        @NonNull Predicate<MetadataBLOBPayloadEntry> prefilter) {
      this.prefilter = prefilter;
      return this;
    }

    /**
     * Set a filter for which metadata entries to allow for a given authenticator during credential
     * registration and metadata lookup.
     *
     * <p>This filter is executed during each execution of {@link #findEntries(List, AAGUID)}, its
     * overloads, and {@link #findTrustRoots(List, Optional)}.
     *
     * <p>The default is {@link Filters#noAttestationKeyCompromise()
     * Filters.noAttestationKeyCompromise()}. Setting a different filter overrides this default; to
     * preserve this condition in addition to the new filter, you must explicitly include the
     * condition in the few filter. For example, by using {@link Filters#allOf(Predicate[])
     * Filters.allOf(Predicate...)}.
     *
     * <p>Note: Returning <code>true</code> in the filter predicate does not automatically make the
     * authenticator trusted, as its attestation certificate must also correctly chain to a trusted
     * attestation root. Rather, returning <code>true</code> in the filter predicate allows the
     * corresponding metadata entry to be used for further trust assessment for that authenticator,
     * while returning <code>false</code> eliminates the metadata entry (and thus any associated
     * trust roots) for the ongoing query.
     *
     * @param filter a {@link Predicate} which returns <code>true</code> for metadata entries to
     *     allow for the corresponding authenticator during credential registration and metadata
     *     lookup.
     * @see #prefilter(Predicate)
     * @see AuthenticatorToBeFiltered
     * @see Filters#allOf(Predicate[])
     */
    public FidoMetadataServiceBuilder filter(
        @NonNull Predicate<FidoMetadataService.Filters.AuthenticatorToBeFiltered> filter) {
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
      return new FidoMetadataService(blob, prefilter, filter, certStore);
    }
  }

  /**
   * Preconfigured filters and utilities for combining filters. See the {@link
   * FidoMetadataServiceBuilder#prefilter(Predicate) prefilter} and {@link
   * FidoMetadataServiceBuilder#filter(Predicate) filter} settings.
   *
   * @see FidoMetadataServiceBuilder#prefilter(Predicate)
   * @see FidoMetadataServiceBuilder#filter(Predicate)
   */
  public static class Filters {

    /**
     * Combine a set of filters into a filter that requires inputs to satisfy ALL of those filters.
     *
     * <p>If <code>filters</code> is empty, then all inputs will satisfy the resulting filter.
     *
     * @param filters A set of filters.
     * @return A filter which only accepts inputs that satisfy ALL of the given <code>
     *     filters</code>.
     */
    public static <T> Predicate<T> allOf(Predicate<T>... filters) {
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

    /**
     * Accept any authenticator whose matched metadata entry does NOT indicate a compromised
     * attestation key.
     *
     * <p>A metadata entry indicates a compromised attestation key if any of its {@link
     * MetadataBLOBPayloadEntry#getStatusReports() statusReports} entries has {@link
     * AuthenticatorStatus#ATTESTATION_KEY_COMPROMISE ATTESTATION_KEY_COMPROMISE} status and either
     * an empty {@link StatusReport#getCertificate() certificate} field or a {@link
     * StatusReport#getCertificate() certificate} whose public key appears in the authenticator's
     * {@link AuthenticatorToBeFiltered#getAttestationCertificateChain() attestation certificate
     * chain}.
     *
     * @see AuthenticatorStatus#ATTESTATION_KEY_COMPROMISE
     */
    public static Predicate<AuthenticatorToBeFiltered> noAttestationKeyCompromise() {
      return (params) ->
          params.getMetadataEntry().getStatusReports().stream()
              .filter(
                  statusReport ->
                      AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE.equals(
                          statusReport.getStatus()))
              .noneMatch(
                  statusReport ->
                      !statusReport.getCertificate().isPresent()
                          || (params.getAttestationCertificateChain().stream()
                              .anyMatch(
                                  cert ->
                                      Arrays.equals(
                                          statusReport
                                              .getCertificate()
                                              .get()
                                              .getPublicKey()
                                              .getEncoded(),
                                          cert.getPublicKey().getEncoded()))));
    }

    /**
     * This class encapsulates parameters for filtering authenticators in the {@link
     * FidoMetadataServiceBuilder#filter(Predicate) filter} setting of {@link FidoMetadataService}.
     */
    @Value
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class AuthenticatorToBeFiltered {

      /**
       * The attestation certificate chain from the <a
       * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#attestation-statement">attestation
       * statement</a> from an authenticator about ot be registered.
       */
      @NonNull List<X509Certificate> attestationCertificateChain;

      /**
       * A metadata BLOB entry that matches the {@link #getAttestationCertificateChain()} and {@link
       * #getAaguid()} in this same {@link AuthenticatorToBeFiltered} object.
       */
      @NonNull MetadataBLOBPayloadEntry metadataEntry;

      AAGUID aaguid;

      /**
       * The AAGUID from the <a
       * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attested-credential-data">attested
       * credential data</a> of a credential about ot be registered.
       *
       * <p>This will not be present if the attested credential data contained an AAGUID of all
       * zeroes.
       */
      public Optional<AAGUID> getAaguid() {
        return Optional.ofNullable(aaguid);
      }
    }
  }

  /**
   * Look up metadata entries matching a given attestation certificate chain or AAGUID.
   *
   * @param attestationCertificateChain an attestation certificate chain, presumably from a WebAuthn
   *     attestation statement.
   * @param aaguid the AAGUID of the authenticator to look up, if available.
   * @return All metadata entries which satisfy ALL of the following:
   *     <ul>
   *       <li>It satisfies the {@link FidoMetadataServiceBuilder#prefilter(Predicate) prefilter}.
   *       <li>It satisfies AT LEAST ONE of the following:
   *           <ul>
   *             <li><code>aaguid</code> is present and equals the {@link
   *                 MetadataBLOBPayloadEntry#getAaguid() AAGUID} of the metadata entry.
   *             <li><code>aaguid</code> is present and equals the {@link
   *                 MetadataBLOBPayloadEntry#getAaguid() AAGUID} of the {@link
   *                 MetadataBLOBPayloadEntry#getMetadataStatement() metadata statement}, if any, in
   *                 the metadata entry.
   *             <li>The certificate subject key identifier of any certificate in <code>
   *                 attestationCertificateChain</code> matches any element of {@link
   *                 MetadataBLOBPayloadEntry#getAttestationCertificateKeyIdentifiers()
   *                 attestationCertificateKeyIdentifiers} in the metadata entry.
   *             <li>The certificate subject key identifier of any certificate in <code>
   *                 attestationCertificateChain</code> matches any element of {@link
   *                 MetadataStatement#getAttestationCertificateKeyIdentifiers()
   *                 attestationCertificateKeyIdentifiers} in the {@link
   *                 MetadataBLOBPayloadEntry#getMetadataStatement() metadata statement}, if any, in
   *                 the metadata entry.
   *           </ul>
   *       <li>It satisfies the {@link FidoMetadataServiceBuilder#filter(Predicate) filter} together
   *           with <code>attestationCertificateChain</code> and <code>aaguid</code>.
   *     </ul>
   *
   * @see #findEntries(List)
   * @see #findEntries(List, AAGUID)
   */
  public Set<MetadataBLOBPayloadEntry> findEntries(
      @NonNull List<X509Certificate> attestationCertificateChain,
      @NonNull Optional<AAGUID> aaguid) {

    final Set<String> certSubjectKeyIdentifiers =
        attestationCertificateChain.stream()
            .map(
                cert -> {
                  try {
                    return new ByteArray(CertificateParser.computeSubjectKeyIdentifier(cert))
                        .getHex();
                  } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(
                        "SHA-1 hash algorithm is not available in JCA context.", e);
                  }
                })
            .collect(Collectors.toSet());

    final Optional<AAGUID> nonzeroAaguid = aaguid.filter(a -> !a.isZero());

    log.debug(
        "findEntries(certSubjectKeyIdentifiers = {}, aaguid = {})",
        certSubjectKeyIdentifiers,
        aaguid);

    if (aaguid.isPresent() && !nonzeroAaguid.isPresent()) {
      log.debug("findEntries: ignoring zero AAGUID");
    }

    final Set<MetadataBLOBPayloadEntry> result =
        Stream.concat(
                nonzeroAaguid
                    .map(prefilteredEntriesByAaguid::get)
                    .map(Collection::stream)
                    .orElseGet(Stream::empty),
                certSubjectKeyIdentifiers.stream()
                    .flatMap(
                        cski ->
                            Optional.ofNullable(
                                    prefilteredEntriesByCertificateKeyIdentifier.get(cski))
                                .map(Collection::stream)
                                .orElseGet(Stream::empty)))
            .filter(
                metadataBLOBPayloadEntry ->
                    this.filter.test(
                        new AuthenticatorToBeFiltered(
                            attestationCertificateChain,
                            metadataBLOBPayloadEntry,
                            nonzeroAaguid.orElse(null))))
            .collect(Collectors.toSet());

    log.debug(
        "findEntries(certSubjectKeyIdentifiers = {}, aaguid = {}) => {} matches",
        certSubjectKeyIdentifiers,
        aaguid,
        result.size());
    return result;
  }

  /**
   * Alias of <code>findEntries(attestationCertificateChain, Optional.empty())</code>.
   *
   * @see #findEntries(List, Optional)
   */
  public Set<MetadataBLOBPayloadEntry> findEntries(
      @NonNull List<X509Certificate> attestationCertificateChain) {
    return findEntries(attestationCertificateChain, Optional.empty());
  }

  /**
   * Alias of <code>findEntries(attestationCertificateChain, Optional.of(aaguid))</code>.
   *
   * @see #findEntries(List, Optional)
   */
  public Set<MetadataBLOBPayloadEntry> findEntries(
      @NonNull List<X509Certificate> attestationCertificateChain, @NonNull AAGUID aaguid) {
    return findEntries(attestationCertificateChain, Optional.of(aaguid));
  }

  /**
   * Find metadata entries matching the credential represented by <code>registrationResult</code>.
   *
   * <p>This is an alias of:
   *
   * <pre>
   * registrationResult.getAttestationTrustPath()
   *   .map(atp -&gt; this.findEntries(atp, new AAGUID(registrationResult.getAaguid())))
   *   .orElseGet(Collections::emptySet)
   * </pre>
   *
   * @see #findEntries(List, Optional)
   */
  public Set<MetadataBLOBPayloadEntry> findEntries(@NonNull RegistrationResult registrationResult) {
    return registrationResult
        .getAttestationTrustPath()
        .map(atp -> findEntries(atp, new AAGUID(registrationResult.getAaguid())))
        .orElseGet(Collections::emptySet);
  }

  /**
   * Find metadata entries matching the given AAGUID.
   *
   * @see #findEntries(List, Optional)
   */
  public Set<MetadataBLOBPayloadEntry> findEntries(@NonNull AAGUID aaguid) {
    return findEntries(Collections.emptyList(), aaguid);
  }

  /**
   * Retrieve metadata entries matching the given filter.
   *
   * <p>Note: The result MAY include fewer results than the number of times the <code>filter</code>
   * returned <code>true</code>, because of possible duplication in the underlying data store.
   *
   * @param filter a {@link Predicate} which returns <code>true</code> for metadata entries to
   *     include in the result.
   * @return All metadata entries which which satisfy the {@link
   *     FidoMetadataServiceBuilder#prefilter(Predicate) prefilter} AND for which the <code>filter
   *     </code> returns <code>true</code>.
   * @see #findEntries(List, Optional)
   */
  public Set<MetadataBLOBPayloadEntry> findEntries(
      @NonNull Predicate<MetadataBLOBPayloadEntry> filter) {
    return Stream.concat(
            Stream.concat(
                prefilteredEntriesByAaguid.values().stream().flatMap(Collection::stream),
                prefilteredEntriesByCertificateKeyIdentifier.values().stream()
                    .flatMap(Collection::stream)),
            prefilteredUnindexedEntries.stream())
        .filter(filter)
        .collect(Collectors.toSet());
  }

  @Override
  public TrustRootsResult findTrustRoots(
      List<X509Certificate> attestationCertificateChain, Optional<ByteArray> aaguid) {
    return TrustRootsResult.builder()
        .trustRoots(
            findEntries(attestationCertificateChain, aaguid.map(AAGUID::new)).stream()
                .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .flatMap(
                    metadataStatement ->
                        metadataStatement.getAttestationRootCertificates().stream())
                .collect(Collectors.toSet()))
        .certStore(certStore)
        .enableRevocationChecking(false)
        .policyTreeValidator(policyNode -> true)
        .build();
  }
}
