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

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.fido.metadata.FidoMetadataDownloaderException.Reason;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.data.exception.HexException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility for downloading, caching and verifying Fido Metadata Service BLOBs and associated
 * certificates.
 *
 * <p>This class is NOT THREAD SAFE since it reads and writes caches. However, it has no internal
 * mutable state, so instances MAY be reused in single-threaded or externally synchronized contexts.
 * See also the {@link #loadCachedBlob()} and {@link #refreshBlob()} methods.
 *
 * <p>Use the {@link #builder() builder} to configure settings, then use the {@link
 * #loadCachedBlob()} and {@link #refreshBlob()} methods to load the metadata BLOB.
 */
@Slf4j
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public final class FidoMetadataDownloader {

  @NonNull private final Set<String> expectedLegalHeaders;
  private final X509Certificate trustRootCertificate;
  private final URL trustRootUrl;
  private final Set<ByteArray> trustRootSha256;
  private final File trustRootCacheFile;
  private final Supplier<Optional<ByteArray>> trustRootCacheSupplier;
  private final Consumer<ByteArray> trustRootCacheConsumer;
  private final String blobJwt;
  private final URL blobUrl;
  private final File blobCacheFile;
  private final Supplier<Optional<ByteArray>> blobCacheSupplier;
  private final Consumer<ByteArray> blobCacheConsumer;
  private final CertStore certStore;
  @NonNull private final Clock clock;
  private final KeyStore httpsTrustStore;

  /**
   * Begin configuring a {@link FidoMetadataDownloader} instance. See the {@link
   * FidoMetadataDownloaderBuilder.Step1 Step1} type.
   *
   * @see FidoMetadataDownloaderBuilder.Step1
   */
  public static FidoMetadataDownloaderBuilder.Step1 builder() {
    return new FidoMetadataDownloaderBuilder.Step1();
  }

  @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
  public static class FidoMetadataDownloaderBuilder {
    @NonNull private final Set<String> expectedLegalHeaders;
    private final X509Certificate trustRootCertificate;
    private final URL trustRootUrl;
    private final Set<ByteArray> trustRootSha256;
    private final File trustRootCacheFile;
    private final Supplier<Optional<ByteArray>> trustRootCacheSupplier;
    private final Consumer<ByteArray> trustRootCacheConsumer;
    private final String blobJwt;
    private final URL blobUrl;
    private final File blobCacheFile;
    private final Supplier<Optional<ByteArray>> blobCacheSupplier;
    private final Consumer<ByteArray> blobCacheConsumer;

    private CertStore certStore = null;
    @NonNull private Clock clock = Clock.systemUTC();
    private KeyStore httpsTrustStore = null;

    public FidoMetadataDownloader build() {
      return new FidoMetadataDownloader(
          expectedLegalHeaders,
          trustRootCertificate,
          trustRootUrl,
          trustRootSha256,
          trustRootCacheFile,
          trustRootCacheSupplier,
          trustRootCacheConsumer,
          blobJwt,
          blobUrl,
          blobCacheFile,
          blobCacheSupplier,
          blobCacheConsumer,
          certStore,
          clock,
          httpsTrustStore);
    }

    /**
     * Step 1: Set the legal header to expect from the FIDO Metadata Service.
     *
     * <p>By using the FIDO Metadata Service, you will be subject to its terms of service. This step
     * serves two purposes:
     *
     * <ol>
     *   <li>To remind you and any code reviewers that you need to read those terms of service
     *       before using this feature.
     *   <li>To help you detect if the legal header changes, so you can take appropriate action.
     * </ol>
     *
     * <p>See {@link Step1#expectLegalHeader(String...)}.
     *
     * @see Step1#expectLegalHeader(String...)
     */
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class Step1 {

      /**
       * Set legal headers expected in the metadata BLOB.
       *
       * <p>By using the FIDO Metadata Service, you will be subject to its terms of service. This
       * builder step serves two purposes:
       *
       * <ol>
       *   <li>To remind you and any code reviewers that you need to read those terms of service
       *       before using this feature.
       *   <li>To help you detect if the legal header changes, so you can take appropriate action.
       * </ol>
       *
       * <p>If the legal header in the downloaded BLOB does not equal any of the <code>
       * expectedLegalHeaders</code>, an {@link UnexpectedLegalHeader} exception will be thrown in
       * the finalizing builder step.
       *
       * <p>Note that this library makes no guarantee that a change to the FIDO Metadata Service
       * terms of service will also cause a change to the legal header in the BLOB.
       *
       * <p>At the time of this library release, the current legal header is <code>
       * "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
       * </code>.
       *
       * @param expectedLegalHeaders the set of BLOB legal headers you expect in the metadata BLOB
       *     payload.
       */
      public Step2 expectLegalHeader(@NonNull String... expectedLegalHeaders) {
        return new Step2(Stream.of(expectedLegalHeaders).collect(Collectors.toSet()));
      }
    }

    /**
     * Step 2: Configure how to retrieve the FIDO Metadata Service trust root certificate when
     * necessary.
     *
     * <p>This step offers three mutually exclusive options:
     *
     * <ol>
     *   <li>Use the default download URL and certificate hash. This is the main intended use case.
     *       See {@link #useDefaultTrustRoot()}.
     *   <li>Use a custom download URL and certificate hash. This is for future-proofing in case the
     *       trust root certificate changes and there is no new release of this library. See {@link
     *       #downloadTrustRoot(URL, Set)}.
     *   <li>Use a pre-retrieved trust root certificate. It is up to you to perform any integrity
     *       checks and cache it as desired. See {@link #useTrustRoot(X509Certificate)}.
     * </ol>
     */
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class Step2 {

      @NonNull private final Set<String> expectedLegalHeaders;

      /**
       * Download the trust root certificate from a hard-coded URL and verify it against a
       * hard-coded SHA-256 hash.
       *
       * <p>This is an alias of:
       *
       * <pre>
       * downloadTrustRoot(
       *   new URL("https://secure.globalsign.com/cacert/root-r3.crt"),
       *   Collections.singleton(ByteArray.fromHex("cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b"))
       * )
       * </pre>
       *
       * This is the current FIDO Metadata Service trust root certificate at the time of this
       * library release.
       *
       * @see #downloadTrustRoot(URL, Set)
       */
      public Step3 useDefaultTrustRoot() {
        try {
          return downloadTrustRoot(
              new URL("https://secure.globalsign.com/cacert/root-r3.crt"),
              Collections.singleton(
                  ByteArray.fromHex(
                      "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b")));
        } catch (MalformedURLException e) {
          throw new RuntimeException(
              "Bad hard-coded trust root certificate URL. Please file a bug report.", e);
        } catch (HexException e) {
          throw new RuntimeException(
              "Bad hard-coded trust root certificate hash. Please file a bug report.", e);
        }
      }

      /**
       * Download the trust root certificate from the given HTTPS <code>url</code> and verify its
       * SHA-256 hash against <code>acceptedCertSha256</code>.
       *
       * <p>The certificate will be downloaded if it does not exist in the cache, or if the cached
       * certificate is not currently valid.
       *
       * <p>If the cert is downloaded, it is also written to the cache {@link File} or {@link
       * Consumer} configured in the {@link Step3 next step}.
       *
       * @param url the HTTP URL to download. It MUST use the <code>https:</code> scheme.
       * @param acceptedCertSha256 a set of SHA-256 hashes to verify the downloaded certificate
       *     against. The downloaded certificate MUST match at least one of these hashes.
       * @throws IllegalArgumentException if <code>url</code> is not a HTTPS URL.
       */
      public Step3 downloadTrustRoot(@NonNull URL url, @NonNull Set<ByteArray> acceptedCertSha256) {
        if (!"https".equals(url.getProtocol())) {
          throw new IllegalArgumentException("Trust certificate download URL must be a HTTPS URL.");
        }
        return new Step3(this, null, url, acceptedCertSha256);
      }

      /**
       * Use the given trust root certificate. It is the caller's responsibility to perform any
       * integrity checks and/or caching logic.
       *
       * @param trustRootCertificate the certificate to use as the FIDO Metadata Service trust root.
       */
      public Step4 useTrustRoot(@NonNull X509Certificate trustRootCertificate) {
        return new Step4(new Step3(this, trustRootCertificate, null, null), null, null, null);
      }
    }

    /**
     * Step 3: Configure how to cache the trust root certificate.
     *
     * <p>This step offers two mutually exclusive options:
     *
     * <ol>
     *   <li>Cache the trust root certificate in a {@link File}. See {@link
     *       Step3#useTrustRootCacheFile(File)}.
     *   <li>Cache the trust root certificate using a {@link Supplier} to read the cache and a
     *       {@link Consumer} to write the cache. See {@link Step3#useTrustRootCache(Supplier,
     *       Consumer)}.
     * </ol>
     */
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class Step3 {
      @NonNull private final Step2 step2;
      private final X509Certificate trustRootCertificate;
      private final URL trustRootUrl;
      private final Set<ByteArray> trustRootSha256;

      /**
       * Cache the trust root certificate in the file <code>cacheFile</code>.
       *
       * <p>If <code>cacheFile</code> exists, is a normal file, is readable, matches one of the
       * SHA-256 hashes configured in the previous step, and contains a currently valid X.509
       * certificate, then it will be used as the trust root for the FIDO Metadata Service blob.
       *
       * <p>Otherwise, the trust root certificate will be downloaded and written to this file.
       */
      public Step4 useTrustRootCacheFile(@NonNull File cacheFile) {
        return new Step4(this, cacheFile, null, null);
      }

      /**
       * Cache the trust root certificate using a {@link Supplier} to read the cache, and using a
       * {@link Consumer} to write the cache.
       *
       * <p>If <code>getCachedTrustRootCert</code> returns non-empty, the value matches one of the
       * SHA-256 hashes configured in the previous step, and is a currently valid X.509 certificate,
       * then it will be used as the trust root for the FIDO Metadata Service blob.
       *
       * <p>Otherwise, the trust root certificate will be downloaded and written to <code>
       * writeCachedTrustRootCert</code>.
       *
       * @param getCachedTrustRootCert a {@link Supplier} that fetches the cached trust root
       *     certificate if it exists. The returned value, if any, should be the trust root
       *     certificate in X.509 DER format.
       * @param writeCachedTrustRootCert a {@link Consumer} that accepts the trust root certificate
       *     in X.509 DER format and writes it to the cache.
       */
      public Step4 useTrustRootCache(
          @NonNull Supplier<Optional<ByteArray>> getCachedTrustRootCert,
          @NonNull Consumer<ByteArray> writeCachedTrustRootCert) {
        return new Step4(this, null, getCachedTrustRootCert, writeCachedTrustRootCert);
      }
    }

    /**
     * Step 4: Configure how to fetch the FIDO Metadata Service metadata BLOB.
     *
     * <p>This step offers three mutually exclusive options:
     *
     * <ol>
     *   <li>Use the default download URL. This is the main intended use case. See {@link
     *       #useDefaultBlob()}.
     *   <li>Use a custom download URL. This is for future-proofing in case the BLOB download URL
     *       changes and there is no new release of this library. See {@link #downloadBlob(URL)}.
     *   <li>Use a pre-retrieved BLOB. The signature will still be verified, but it is up to you to
     *       renew it when appropriate and perform any caching as desired. See {@link
     *       #useBlob(String)}.
     * </ol>
     */
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class Step4 {
      @NonNull private final Step3 step3;
      private final File trustRootCacheFile;
      private final Supplier<Optional<ByteArray>> trustRootCacheSupplier;
      private final Consumer<ByteArray> trustRootCacheConsumer;

      /**
       * Download the metadata BLOB from a hard-coded URL.
       *
       * <p>This is an alias of <code>downloadBlob(new URL("https://mds.fidoalliance.org/"))</code>.
       *
       * <p>This is the current FIDO Metadata Service BLOB download URL at the time of this library
       * release.
       *
       * @see #downloadBlob(URL)
       */
      public Step5 useDefaultBlob() {
        try {
          return downloadBlob(new URL("https://mds.fidoalliance.org/"));
        } catch (MalformedURLException e) {
          throw new RuntimeException(
              "Bad hard-coded trust root certificate URL. Please file a bug report.", e);
        }
      }

      /**
       * Download the metadata BLOB from the given HTTPS <code>url</code>.
       *
       * <p>The BLOB will be downloaded if it does not exist in the cache, or if the <code>
       * nextUpdate</code> property of the cached BLOB is the current date or earlier.
       *
       * <p>If the BLOB is downloaded, it is also written to the cache {@link File} or {@link
       * Consumer} configured in the next step.
       *
       * @param url the HTTP URL to download. It MUST use the <code>https:</code> scheme.
       */
      public Step5 downloadBlob(@NonNull URL url) {
        return new Step5(this, null, url);
      }

      /**
       * Use the given metadata BLOB; never download it.
       *
       * <p>The blob signature and trust chain will still be verified, but it is the caller's
       * responsibility to renew the metadata BLOB according to the <a
       * href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules">FIDO
       * Metadata Service specification</a>.
       *
       * @param blobJwt the Metadata BLOB in JWT format as defined in <a
       *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">FIDO
       *     Metadata Service §3.1.7. Metadata BLOB</a>. The byte array should not be
       *     Base64-decoded.
       * @see <a
       *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob">FIDO
       *     Metadata Service §3.1.7. Metadata BLOB</a>
       * @see <a
       *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules">FIDO
       *     Metadata Service §3.2. Metadata BLOB object processing rules</a>
       */
      public FidoMetadataDownloaderBuilder useBlob(@NonNull String blobJwt) {
        return finishRequiredSteps(new Step5(this, blobJwt, null), null, null, null);
      }
    }

    /**
     * Step 5: Configure how to cache the metadata BLOB.
     *
     * <p>This step offers two mutually exclusive options:
     *
     * <ol>
     *   <li>Cache the metadata BLOB in a {@link File}. See {@link Step5#useBlobCacheFile(File)}.
     *   <li>Cache the metadata BLOB using a {@link Supplier} to read the cache and a {@link
     *       Consumer} to write the cache. See {@link Step5#useBlobCache(Supplier, Consumer)}.
     * </ol>
     */
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class Step5 {
      @NonNull private final Step4 step4;
      private final String blobJwt;
      private final URL blobUrl;

      /**
       * Cache metadata BLOB in the file <code>cacheFile</code>.
       *
       * <p>If <code>cacheFile</code> exists, is a normal file, is readable, and is not out of date,
       * then it will be used as the FIDO Metadata Service BLOB.
       *
       * <p>Otherwise, the metadata BLOB will be downloaded and written to this file.
       *
       * @param cacheFile a {@link File} which may or may not exist. If it exists, it should contain
       *     the metadata BLOB in JWS compact serialization format <a
       *     href="https://datatracker.ietf.org/doc/html/rfc7515#section-3.1">[RFC7515]</a>.
       */
      public FidoMetadataDownloaderBuilder useBlobCacheFile(@NonNull File cacheFile) {
        return finishRequiredSteps(this, cacheFile, null, null);
      }

      /**
       * Cache the metadata BLOB using a {@link Supplier} to read the cache, and using a {@link
       * Consumer} to write the cache.
       *
       * <p>If <code>getCachedBlob</code> returns non-empty and the content is not out of date, then
       * it will be used as the FIDO Metadata Service BLOB.
       *
       * <p>Otherwise, the metadata BLOB will be downloaded and written to <code>writeCachedBlob
       * </code>.
       *
       * @param getCachedBlob a {@link Supplier} that fetches the cached metadata BLOB if it exists.
       *     The returned value, if any, should be in JWS compact serialization format <a
       *     href="https://datatracker.ietf.org/doc/html/rfc7515#section-3.1">[RFC7515]</a>.
       * @param writeCachedBlob a {@link Consumer} that accepts the metadata BLOB in JWS compact
       *     serialization format <a
       *     href="https://datatracker.ietf.org/doc/html/rfc7515#section-3.1">[RFC7515]</a> and
       *     writes it to the cache.
       */
      public FidoMetadataDownloaderBuilder useBlobCache(
          @NonNull Supplier<Optional<ByteArray>> getCachedBlob,
          @NonNull Consumer<ByteArray> writeCachedBlob) {
        return finishRequiredSteps(this, null, getCachedBlob, writeCachedBlob);
      }
    }

    private static FidoMetadataDownloaderBuilder finishRequiredSteps(
        FidoMetadataDownloaderBuilder.Step5 step5,
        File blobCacheFile,
        Supplier<Optional<ByteArray>> blobCacheSupplier,
        Consumer<ByteArray> blobCacheConsumer) {
      return new FidoMetadataDownloaderBuilder(
          step5.step4.step3.step2.expectedLegalHeaders,
          step5.step4.step3.trustRootCertificate,
          step5.step4.step3.trustRootUrl,
          step5.step4.step3.trustRootSha256,
          step5.step4.trustRootCacheFile,
          step5.step4.trustRootCacheSupplier,
          step5.step4.trustRootCacheConsumer,
          step5.blobJwt,
          step5.blobUrl,
          blobCacheFile,
          blobCacheSupplier,
          blobCacheConsumer);
    }

    /**
     * Use <code>clock</code> as the source of the current time for some application-level logic.
     *
     * <p>This is primarily intended for testing.
     *
     * <p>The default is {@link Clock#systemUTC()}.
     *
     * @param clock a {@link Clock} which the finished {@link FidoMetadataDownloader} will use to
     *     tell the time.
     */
    public FidoMetadataDownloaderBuilder clock(@NonNull Clock clock) {
      this.clock = clock;
      return this;
    }

    /**
     * Use the provided CRLs.
     *
     * <p>CRLs will also be downloaded from distribution points if the <code>
     * com.sun.security.enableCRLDP</code> system property is set to <code>true</code> (assuming the
     * use of the {@link CertPathValidator} implementation from the SUN provider).
     *
     * @throws InvalidAlgorithmParameterException if {@link CertStore#getInstance(String,
     *     CertStoreParameters)} does.
     * @throws NoSuchAlgorithmException if a <code>"Collection"</code> type {@link CertStore}
     *     provider is not available.
     * @see #useCrls(CertStore)
     */
    public FidoMetadataDownloaderBuilder useCrls(@NonNull Collection<CRL> crls)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
      return useCrls(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls)));
    }

    /**
     * Use CRLs in the provided {@link CertStore}.
     *
     * <p>CRLs will also be downloaded from distribution points if the <code>
     * com.sun.security.enableCRLDP</code> system property is set to <code>true</code> (assuming the
     * use of the {@link CertPathValidator} implementation from the SUN provider).
     *
     * @see #useCrls(Collection)
     */
    public FidoMetadataDownloaderBuilder useCrls(CertStore certStore) {
      this.certStore = certStore;
      return this;
    }

    /**
     * Use the provided {@link X509Certificate}s as trust roots for HTTPS downloads.
     *
     * <p>This is primarily useful when setting {@link Step2#downloadTrustRoot(URL, Set)
     * downloadTrustRoot} and/or {@link Step4#downloadBlob(URL) downloadBlob} to download from
     * custom servers instead of the defaults.
     *
     * <p>If provided, these will be used for downloading
     *
     * <ul>
     *   <li>the trust root certificate for the BLOB signature chain, and
     *   <li>the metadata BLOB.
     * </ul>
     *
     * If not set, the system default certificate store will be used.
     */
    public FidoMetadataDownloaderBuilder trustHttpsCerts(@NonNull X509Certificate... certificates) {
      final KeyStore trustStore;
      try {
        trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);
      } catch (KeyStoreException
          | IOException
          | NoSuchAlgorithmException
          | CertificateException e) {
        throw new RuntimeException(
            "Failed to instantiate or initialize KeyStore. This should not be possible, please file a bug report.",
            e);
      }
      for (X509Certificate cert : certificates) {
        try {
          trustStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
        } catch (KeyStoreException e) {
          throw new RuntimeException(
              "Failed to import HTTPS cert into KeyStore. This should not be possible, please file a bug report.",
              e);
        }
      }
      this.httpsTrustStore = trustStore;

      return this;
    }
  }

  /**
   * Load the metadata BLOB from cache, or download a fresh one if necessary.
   *
   * <p>This method is NOT THREAD SAFE since it reads and writes caches.
   *
   * <p>On each execution this will, in order:
   *
   * <ol>
   *   <li>Download the trust root certificate, if necessary: if the cache is empty, the cache fails
   *       to load, or the cached cert is not valid at the current time (as determined by the {@link
   *       FidoMetadataDownloaderBuilder#clock(Clock) clock} setting).
   *   <li>If downloaded, cache the trust root certificate using the configured {@link File} or
   *       {@link Consumer} (see {@link FidoMetadataDownloaderBuilder.Step3})
   *   <li>Download the metadata BLOB, if necessary: if the cache is empty, the cache fails to load,
   *       or the <code>"nextUpdate"</code> property in the cached BLOB is the current date (as
   *       determined by the {@link FidoMetadataDownloaderBuilder#clock(Clock) clock} setting) or
   *       earlier.
   *   <li>Check the <code>"no"</code> property of the downloaded BLOB, if any, and compare it with
   *       the <code>"no"</code> of the cached BLOB, if any. The one with a greater <code>"no"
   *       </code> overrides the other, even if its <code>"nextUpdate"</code> is in the past.
   *   <li>If a BLOB with a newer <code>"no"</code> was downloaded, verify that the value of its
   *       <code>"legalHeader"</code> appears in the configured {@link
   *       FidoMetadataDownloaderBuilder.Step1#expectLegalHeader(String...) expectLegalHeader}
   *       setting. If not, throw an {@link UnexpectedLegalHeader} exception containing the cached
   *       BLOB, if any, and the downloaded BLOB.
   *   <li>If a BLOB with a newer <code>"no"</code> was downloaded and had an expected <code>
   *       "legalHeader"</code>, cache the new BLOB using the configured {@link File} or {@link
   *       Consumer} (see {@link FidoMetadataDownloaderBuilder.Step5}).
   * </ol>
   *
   * No internal mutable state is maintained between invocations of this method; each invocation
   * will reload/rewrite caches, perform downloads and check the <code>"legalHeader"
   * </code> as necessary. You may therefore reuse a {@link FidoMetadataDownloader} instance and,
   * for example, call this method periodically to refresh the BLOB when appropriate. Each call will
   * return a new {@link MetadataBLOB} instance; ones already returned will not be updated by
   * subsequent calls.
   *
   * @return the successfully retrieved and validated metadata BLOB.
   * @throws Base64UrlException if the explicitly configured or newly downloaded BLOB is not a
   *     well-formed JWT in compact serialization.
   * @throws CertPathValidatorException if the explicitly configured or newly downloaded BLOB fails
   *     certificate path validation.
   * @throws CertificateException if the trust root certificate was downloaded and passed the
   *     SHA-256 integrity check, but does not contain a currently valid X.509 DER certificate; or
   *     if the BLOB signing certificate chain fails to parse.
   * @throws DigestException if the trust root certificate was downloaded but failed the SHA-256
   *     integrity check.
   * @throws FidoMetadataDownloaderException if the explicitly configured or newly downloaded BLOB
   *     (if any) has a bad signature and there is no cached BLOB to fall back to.
   * @throws IOException if any of the following fails: downloading the trust root certificate,
   *     downloading the BLOB, reading or writing any cache file (if any), or parsing the BLOB
   *     contents.
   * @throws InvalidAlgorithmParameterException if certificate path validation fails.
   * @throws InvalidKeyException if signature verification fails.
   * @throws NoSuchAlgorithmException if signature verification fails, or if the SHA-256 algorithm
   *     is not available.
   * @throws SignatureException if signature verification fails.
   * @throws UnexpectedLegalHeader if the downloaded BLOB (if any) contains a <code>"legalHeader"
   *     </code> value not configured in {@link
   *     FidoMetadataDownloaderBuilder.Step1#expectLegalHeader(String...)
   *     expectLegalHeader(String...)} but is otherwise valid. The downloaded BLOB will not be
   *     written to cache in this case.
   */
  public MetadataBLOB loadCachedBlob()
      throws CertPathValidatorException, InvalidAlgorithmParameterException, Base64UrlException,
          CertificateException, IOException, NoSuchAlgorithmException, SignatureException,
          InvalidKeyException, UnexpectedLegalHeader, DigestException,
          FidoMetadataDownloaderException {
    final X509Certificate trustRoot = retrieveTrustRootCert();

    final Optional<MetadataBLOB> explicit = loadExplicitBlobOnly(trustRoot);
    if (explicit.isPresent()) {
      log.debug("Explicit BLOB is set - disregarding cache and download.");
      return explicit.get();
    }

    final Optional<MetadataBLOB> cached = loadCachedBlobOnly(trustRoot);
    if (cached.isPresent()) {
      log.debug("Cached BLOB exists, checking expiry date...");
      if (cached
          .get()
          .getPayload()
          .getNextUpdate()
          .atStartOfDay()
          .atZone(clock.getZone())
          .isAfter(clock.instant().atZone(clock.getZone()))) {
        log.debug("Cached BLOB has not yet expired - using cached BLOB.");
        return cached.get();
      } else {
        log.debug("Cached BLOB has expired.");
      }

    } else {
      log.debug("Cached BLOB does not exist or is invalid.");
    }

    return refreshBlobInternal(trustRoot, cached).get();
  }

  /**
   * Download and cache a fresh metadata BLOB, or read it from cache if the downloaded BLOB is not
   * up to date.
   *
   * <p>This method is NOT THREAD SAFE since it reads and writes caches.
   *
   * <p>On each execution this will, in order:
   *
   * <ol>
   *   <li>Download the trust root certificate, if necessary: if the cache is empty, the cache fails
   *       to load, or the cached cert is not valid at the current time (as determined by the {@link
   *       FidoMetadataDownloaderBuilder#clock(Clock) clock} setting).
   *   <li>If downloaded, cache the trust root certificate using the configured {@link File} or
   *       {@link Consumer} (see {@link FidoMetadataDownloaderBuilder.Step3})
   *   <li>Download the metadata BLOB.
   *   <li>Check the <code>"no"</code> property of the downloaded BLOB and compare it with the
   *       <code>"no"</code> of the cached BLOB, if any. The one with a greater <code>"no"
   *       </code> overrides the other, even if its <code>"nextUpdate"</code> is in the past.
   *   <li>If the downloaded BLOB has a newer <code>"no"</code>, or if no BLOB was cached, verify
   *       that the value of the downloaded BLOB's <code>"legalHeader"</code> appears in the
   *       configured {@link FidoMetadataDownloaderBuilder.Step1#expectLegalHeader(String...)
   *       expectLegalHeader} setting. If not, throw an {@link UnexpectedLegalHeader} exception
   *       containing the cached BLOB, if any, and the downloaded BLOB.
   *   <li>If the downloaded BLOB has an expected <code>
   *       "legalHeader"</code>, cache it using the configured {@link File} or {@link Consumer} (see
   *       {@link FidoMetadataDownloaderBuilder.Step5}).
   * </ol>
   *
   * No internal mutable state is maintained between invocations of this method; each invocation
   * will reload/rewrite caches, perform downloads and check the <code>"legalHeader"
   * </code> as necessary. You may therefore reuse a {@link FidoMetadataDownloader} instance and,
   * for example, call this method periodically to refresh the BLOB. Each call will return a new
   * {@link MetadataBLOB} instance; ones already returned will not be updated by subsequent calls.
   *
   * @return the successfully retrieved and validated metadata BLOB.
   * @throws Base64UrlException if the explicitly configured or newly downloaded BLOB is not a
   *     well-formed JWT in compact serialization.
   * @throws CertPathValidatorException if the explicitly configured or newly downloaded BLOB fails
   *     certificate path validation.
   * @throws CertificateException if the trust root certificate was downloaded and passed the
   *     SHA-256 integrity check, but does not contain a currently valid X.509 DER certificate; or
   *     if the BLOB signing certificate chain fails to parse.
   * @throws DigestException if the trust root certificate was downloaded but failed the SHA-256
   *     integrity check.
   * @throws FidoMetadataDownloaderException if the explicitly configured or newly downloaded BLOB
   *     (if any) has a bad signature and there is no cached BLOB to fall back to.
   * @throws IOException if any of the following fails: downloading the trust root certificate,
   *     downloading the BLOB, reading or writing any cache file (if any), or parsing the BLOB
   *     contents.
   * @throws InvalidAlgorithmParameterException if certificate path validation fails.
   * @throws InvalidKeyException if signature verification fails.
   * @throws NoSuchAlgorithmException if signature verification fails, or if the SHA-256 algorithm
   *     is not available.
   * @throws SignatureException if signature verification fails.
   * @throws UnexpectedLegalHeader if the downloaded BLOB (if any) contains a <code>"legalHeader"
   *     </code> value not configured in {@link
   *     FidoMetadataDownloaderBuilder.Step1#expectLegalHeader(String...)
   *     expectLegalHeader(String...)} but is otherwise valid. The downloaded BLOB will not be
   *     written to cache in this case.
   */
  public MetadataBLOB refreshBlob()
      throws CertPathValidatorException, InvalidAlgorithmParameterException, Base64UrlException,
          CertificateException, IOException, NoSuchAlgorithmException, SignatureException,
          InvalidKeyException, UnexpectedLegalHeader, DigestException,
          FidoMetadataDownloaderException {
    final X509Certificate trustRoot = retrieveTrustRootCert();

    final Optional<MetadataBLOB> explicit = loadExplicitBlobOnly(trustRoot);
    if (explicit.isPresent()) {
      log.debug("Explicit BLOB is set - disregarding cache and download.");
      return explicit.get();
    }

    final Optional<MetadataBLOB> cached = loadCachedBlobOnly(trustRoot);
    if (cached.isPresent()) {
      log.debug("Cached BLOB exists, proceeding to compare against fresh BLOB...");
    } else {
      log.debug("Cached BLOB does not exist or is invalid.");
    }

    return refreshBlobInternal(trustRoot, cached).get();
  }

  private Optional<MetadataBLOB> refreshBlobInternal(
      @NonNull X509Certificate trustRoot, @NonNull Optional<MetadataBLOB> cached)
      throws CertPathValidatorException, InvalidAlgorithmParameterException, Base64UrlException,
          CertificateException, IOException, NoSuchAlgorithmException, SignatureException,
          InvalidKeyException, UnexpectedLegalHeader, FidoMetadataDownloaderException {

    try {
      log.debug("Attempting to download new BLOB...");
      final ByteArray downloadedBytes = download(blobUrl);
      final MetadataBLOB downloadedBlob = parseAndVerifyBlob(downloadedBytes, trustRoot);
      log.debug("New BLOB downloaded.");

      if (cached.isPresent()) {
        log.debug("Cached BLOB exists - checking if new BLOB has a higher \"no\"...");
        if (downloadedBlob.getPayload().getNo() <= cached.get().getPayload().getNo()) {
          log.debug("New BLOB does not have a higher \"no\" - using cached BLOB instead.");
          return cached;
        }
        log.debug("New BLOB has a higher \"no\" - proceeding with new BLOB.");
      }

      log.debug("Checking legalHeader in new BLOB...");
      if (!expectedLegalHeaders.contains(downloadedBlob.getPayload().getLegalHeader())) {
        throw new UnexpectedLegalHeader(cached.orElse(null), downloadedBlob);
      }

      log.debug("Writing new BLOB to cache...");
      if (blobCacheFile != null) {
        try (FileOutputStream f = new FileOutputStream(blobCacheFile)) {
          f.write(downloadedBytes.getBytes());
        }
      }

      if (blobCacheConsumer != null) {
        blobCacheConsumer.accept(downloadedBytes);
      }

      return Optional.of(downloadedBlob);
    } catch (FidoMetadataDownloaderException e) {
      if (e.getReason() == Reason.BAD_SIGNATURE && cached.isPresent()) {
        log.warn("New BLOB has bad signature - falling back to cached BLOB.");
        return cached;
      } else {
        throw e;
      }
    } catch (Exception e) {
      if (cached.isPresent()) {
        log.warn("Failed to download new BLOB - falling back to cached BLOB.", e);
        return cached;
      } else {
        throw e;
      }
    }
  }

  /**
   * @throws CertificateException if the trust root certificate was downloaded and passed the
   *     SHA-256 integrity check, but does not contain a currently valid X.509 DER certificate.
   * @throws DigestException if the trust root certificate was downloaded but failed the SHA-256
   *     integrity check.
   * @throws IOException if the trust root certificate download failed, or if reading or writing the
   *     cache file (if any) failed.
   * @throws NoSuchAlgorithmException if the SHA-256 algorithm is not available.
   */
  private X509Certificate retrieveTrustRootCert()
      throws CertificateException, DigestException, IOException, NoSuchAlgorithmException {

    if (trustRootCertificate != null) {
      return trustRootCertificate;

    } else {
      final Optional<ByteArray> cachedContents;
      if (trustRootCacheFile != null) {
        cachedContents = readCacheFile(trustRootCacheFile);
      } else {
        cachedContents = trustRootCacheSupplier.get();
      }

      X509Certificate cert = null;
      if (cachedContents.isPresent()) {
        final ByteArray verifiedCachedContents = verifyHash(cachedContents.get(), trustRootSha256);
        if (verifiedCachedContents != null) {
          try {
            final X509Certificate cachedCert =
                CertificateParser.parseDer(verifiedCachedContents.getBytes());
            cachedCert.checkValidity(Date.from(clock.instant()));
            cert = cachedCert;
          } catch (CertificateException e) {
            // Fall through
          }
        }
      }

      if (cert == null) {
        final ByteArray downloaded = verifyHash(download(trustRootUrl), trustRootSha256);
        if (downloaded == null) {
          throw new DigestException(
              "Downloaded trust root certificate matches none of the acceptable hashes.");
        }

        cert = CertificateParser.parseDer(downloaded.getBytes());
        cert.checkValidity(Date.from(clock.instant()));

        if (trustRootCacheFile != null) {
          try (FileOutputStream f = new FileOutputStream(trustRootCacheFile)) {
            f.write(downloaded.getBytes());
          }
        }

        if (trustRootCacheConsumer != null) {
          trustRootCacheConsumer.accept(downloaded);
        }
      }

      return cert;
    }
  }

  /**
   * @throws Base64UrlException if the metadata BLOB is not a well-formed JWT in compact
   *     serialization.
   * @throws CertPathValidatorException if the explicitly configured BLOB fails certificate path
   *     validation.
   * @throws CertificateException if the BLOB signing certificate chain fails to parse.
   * @throws IOException on failure to parse the BLOB contents.
   * @throws InvalidAlgorithmParameterException if certificate path validation fails.
   * @throws InvalidKeyException if signature verification fails.
   * @throws NoSuchAlgorithmException if signature verification fails.
   * @throws SignatureException if signature verification fails.
   * @throws FidoMetadataDownloaderException if the explicitly configured BLOB (if any) has a bad
   *     signature.
   */
  private Optional<MetadataBLOB> loadExplicitBlobOnly(X509Certificate trustRootCertificate)
      throws Base64UrlException, CertPathValidatorException, CertificateException, IOException,
          InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
          SignatureException, FidoMetadataDownloaderException {
    if (blobJwt != null) {
      return Optional.of(
          parseAndVerifyBlob(
              new ByteArray(blobJwt.getBytes(StandardCharsets.UTF_8)), trustRootCertificate));

    } else {
      return Optional.empty();
    }
  }

  private Optional<MetadataBLOB> loadCachedBlobOnly(X509Certificate trustRootCertificate) {

    final Optional<ByteArray> cachedContents;
    if (blobCacheFile != null) {
      log.debug("Attempting to read BLOB from cache file...");

      try {
        cachedContents = readCacheFile(blobCacheFile);
      } catch (IOException e) {
        return Optional.empty();
      }
    } else {
      log.debug("Attempting to read BLOB from cache Supplier...");
      cachedContents = blobCacheSupplier.get();
    }

    return cachedContents.map(
        cached -> {
          try {
            return parseAndVerifyBlob(cached, trustRootCertificate);
          } catch (Exception e) {
            log.warn("Failed to read or parse cached BLOB.", e);
            return null;
          }
        });
  }

  private Optional<ByteArray> readCacheFile(File cacheFile) throws IOException {
    if (cacheFile.exists() && cacheFile.canRead() && cacheFile.isFile()) {
      try (FileInputStream f = new FileInputStream(cacheFile)) {
        return Optional.of(readAll(f));
      } catch (FileNotFoundException e) {
        throw new RuntimeException(
            "This exception should be impossible, please file a bug report.", e);
      }
    } else {
      return Optional.empty();
    }
  }

  private ByteArray download(URL url) throws IOException {
    URLConnection conn = url.openConnection();

    if (conn instanceof HttpsURLConnection) {
      HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
      if (httpsTrustStore != null) {
        try {
          TrustManagerFactory trustMan =
              TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
          trustMan.init(httpsTrustStore);
          SSLContext sslContext = SSLContext.getInstance("TLS");
          sslContext.init(null, trustMan.getTrustManagers(), null);

          httpsConn.setSSLSocketFactory(sslContext.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
          throw new RuntimeException(
              "Failed to initialize HTTPS trust store. This should be impossible, please file a bug report.",
              e);
        }
      }
      httpsConn.setRequestMethod("GET");
    }

    return readAll(conn.getInputStream());
  }

  private MetadataBLOB parseAndVerifyBlob(ByteArray jwt, X509Certificate trustRootCertificate)
      throws CertPathValidatorException, InvalidAlgorithmParameterException, CertificateException,
          IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
          Base64UrlException, FidoMetadataDownloaderException {
    Scanner s = new Scanner(new ByteArrayInputStream(jwt.getBytes())).useDelimiter("\\.");
    final ByteArray header = ByteArray.fromBase64Url(s.next());
    final ByteArray payload = ByteArray.fromBase64Url(s.next());
    final ByteArray signature = ByteArray.fromBase64Url(s.next());
    return verifyBlob(header, payload, signature, trustRootCertificate);
  }

  private MetadataBLOB verifyBlob(
      ByteArray jwtHeader,
      ByteArray jwtPayload,
      ByteArray jwtSignature,
      X509Certificate trustRootCertificate)
      throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException,
          SignatureException, CertPathValidatorException, InvalidAlgorithmParameterException,
          FidoMetadataDownloaderException {
    final ObjectMapper headerJsonMapper =
        com.yubico.internal.util.JacksonCodecs.json()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .setBase64Variant(Base64Variants.MIME_NO_LINEFEEDS);
    final MetadataBLOBHeader header =
        headerJsonMapper.readValue(jwtHeader.getBytes(), MetadataBLOBHeader.class);

    final List<X509Certificate> certChain;
    if (header.getX5u().isPresent()) {
      final URL x5u = header.getX5u().get();
      if (blobUrl != null
          && (!(x5u.getHost().equals(blobUrl.getHost())
              && x5u.getProtocol().equals(blobUrl.getProtocol())
              && x5u.getPort() == blobUrl.getPort()))) {
        throw new IllegalArgumentException(
            String.format(
                "x5u in BLOB header must have same origin as the URL the BLOB was downloaded from. Expected origin of: %s ; found: %s",
                blobUrl, x5u));
      }
      List<X509Certificate> certs = new ArrayList<>();
      for (String pem :
          new String(download(x5u).getBytes(), StandardCharsets.UTF_8)
              .trim()
              .split("\\n+-----END CERTIFICATE-----\\n+-----BEGIN CERTIFICATE-----\\n+")) {
        X509Certificate x509Certificate = CertificateParser.parsePem(pem);
        certs.add(x509Certificate);
      }
      certChain = certs;
    } else if (header.getX5c().isPresent()) {
      certChain = header.getX5c().get();
    } else {
      certChain = Collections.singletonList(trustRootCertificate);
    }

    final X509Certificate leafCert = certChain.get(0);

    final Signature signature;
    switch (header.getAlg()) {
      case "RS256":
        signature = Signature.getInstance("SHA256withRSA");
        break;

      case "ES256":
        signature = Signature.getInstance("SHA256withECDSA");
        break;

      default:
        throw new UnsupportedOperationException(
            "Unimplemented JWT verification algorithm: " + header.getAlg());
    }

    signature.initVerify(leafCert.getPublicKey());
    signature.update(
        (jwtHeader.getBase64Url() + "." + jwtPayload.getBase64Url())
            .getBytes(StandardCharsets.UTF_8));
    if (!signature.verify(jwtSignature.getBytes())) {
      throw new FidoMetadataDownloaderException(Reason.BAD_SIGNATURE);
    }

    final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    final CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
    final CertPath blobCertPath = certFactory.generateCertPath(certChain);
    final PKIXParameters pathParams =
        new PKIXParameters(Collections.singleton(new TrustAnchor(trustRootCertificate, null)));
    if (certStore != null) {
      pathParams.addCertStore(certStore);
    }
    pathParams.setDate(Date.from(clock.instant()));
    cpv.validate(blobCertPath, pathParams);

    return new MetadataBLOB(
        header,
        JacksonCodecs.jsonWithDefaultEnums()
            .readValue(jwtPayload.getBytes(), MetadataBLOBPayload.class));
  }

  private static ByteArray readAll(InputStream is) throws IOException {
    return new ByteArray(BinaryUtil.readAll(is));
  }

  /**
   * @return <code>contents</code> if its SHA-256 hash matches any element of <code>
   *     acceptedCertSha256</code>, otherwise <code>null</code>.
   */
  private static ByteArray verifyHash(ByteArray contents, Set<ByteArray> acceptedCertSha256)
      throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    final ByteArray hash = new ByteArray(digest.digest(contents.getBytes()));
    if (acceptedCertSha256.stream().anyMatch(acceptableHash -> acceptableHash.equals(hash))) {
      return contents;
    } else {
      return null;
    }
  }
}
