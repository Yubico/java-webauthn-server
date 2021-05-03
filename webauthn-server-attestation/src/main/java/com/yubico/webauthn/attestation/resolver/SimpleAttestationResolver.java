// Copyright (c) 2018, Yubico AB
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

package com.yubico.webauthn.attestation.resolver;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.OptionalUtil;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.AttestationResolver;
import com.yubico.webauthn.attestation.DeviceMatcher;
import com.yubico.webauthn.attestation.MetadataObject;
import com.yubico.webauthn.attestation.Transport;
import com.yubico.webauthn.attestation.TrustResolver;
import com.yubico.webauthn.attestation.matcher.ExtensionMatcher;
import com.yubico.webauthn.attestation.matcher.FingerprintMatcher;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.NonNull;

public final class SimpleAttestationResolver implements AttestationResolver {

  private static final String SELECTORS = "selectors";
  private static final String SELECTOR_TYPE = "type";
  private static final String SELECTOR_PARAMETERS = "parameters";

  private static final String TRANSPORTS = "transports";
  private static final String TRANSPORTS_EXT_OID = "1.3.6.1.4.1.45724.2.1.1";

  private static final Map<String, DeviceMatcher> DEFAULT_DEVICE_MATCHERS =
      ImmutableMap.of(
          ExtensionMatcher.SELECTOR_TYPE, new ExtensionMatcher(),
          FingerprintMatcher.SELECTOR_TYPE, new FingerprintMatcher());

  private final Map<X509Certificate, MetadataObject> metadata = new HashMap<>();
  private final TrustResolver trustResolver;
  private final Map<String, DeviceMatcher> matchers;

  public SimpleAttestationResolver(
      @NonNull Collection<MetadataObject> objects,
      @NonNull TrustResolver trustResolver,
      @NonNull Map<String, DeviceMatcher> matchers)
      throws CertificateException {
    for (MetadataObject object : objects) {
      for (String caPem : object.getTrustedCertificates()) {
        X509Certificate trustAnchor = CertificateParser.parsePem(caPem);
        metadata.put(trustAnchor, object);
      }
    }

    this.trustResolver = trustResolver;
    this.matchers = CollectionUtil.immutableMap(matchers);
  }

  public SimpleAttestationResolver(Collection<MetadataObject> objects, TrustResolver trustResolver)
      throws CertificateException {
    this(objects, trustResolver, DEFAULT_DEVICE_MATCHERS);
  }

  private Optional<MetadataObject> lookupTrustAnchor(X509Certificate trustAnchor) {
    return Optional.ofNullable(metadata.get(trustAnchor));
  }

  @Override
  public Optional<Attestation> resolve(
      X509Certificate attestationCertificate, List<X509Certificate> certificateChain) {
    Optional<X509Certificate> trustAnchor =
        trustResolver.resolveTrustAnchor(attestationCertificate, certificateChain);

    return trustAnchor
        .flatMap(this::lookupTrustAnchor)
        .map(
            metadata -> {
              Map<String, String> vendorProperties;
              Map<String, String> deviceProperties = null;
              String identifier;
              int metadataTransports = 0;

              identifier = metadata.getIdentifier();
              vendorProperties = Maps.filterValues(metadata.getVendorInfo(), Objects::nonNull);
              for (JsonNode device : metadata.getDevices()) {
                if (deviceMatches(device.get(SELECTORS), attestationCertificate)) {
                  JsonNode transportNode = device.get(TRANSPORTS);
                  if (transportNode != null) {
                    metadataTransports |= transportNode.asInt(0);
                  }
                  ImmutableMap.Builder<String, String> devicePropertiesBuilder =
                      ImmutableMap.builder();
                  for (Map.Entry<String, JsonNode> deviceEntry :
                      Lists.newArrayList(device.fields())) {
                    JsonNode value = deviceEntry.getValue();
                    if (value.isTextual()) {
                      devicePropertiesBuilder.put(deviceEntry.getKey(), value.asText());
                    }
                  }
                  deviceProperties = devicePropertiesBuilder.build();
                  break;
                }
              }

              return Attestation.builder()
                  .trusted(true)
                  .metadataIdentifier(Optional.ofNullable(identifier))
                  .vendorProperties(Optional.of(vendorProperties))
                  .deviceProperties(Optional.ofNullable(deviceProperties))
                  .transports(
                      OptionalUtil.zipWith(
                              getTransports(attestationCertificate),
                              Optional.of(metadataTransports).filter(t -> t != 0),
                              (a, b) -> a | b)
                          .map(Transport::fromInt))
                  .build();
            });
  }

  private boolean deviceMatches(
      JsonNode selectors, @NonNull X509Certificate attestationCertificate) {
    if (selectors == null || selectors.isNull()) {
      return true;
    } else {
      for (JsonNode selector : selectors) {
        DeviceMatcher matcher = matchers.get(selector.get(SELECTOR_TYPE).asText());
        if (matcher != null
            && matcher.matches(attestationCertificate, selector.get(SELECTOR_PARAMETERS))) {
          return true;
        }
      }
      return false;
    }
  }

  private static Optional<Integer> getTransports(X509Certificate cert) {
    byte[] extensionValue = cert.getExtensionValue(TRANSPORTS_EXT_OID);

    if (extensionValue == null) {
      return Optional.empty();
    }

    ExceptionUtil.assure(
        extensionValue.length >= 4,
        "Transports extension value must be at least 4 bytes (2 bytes octet string header, 2 bytes bit string header), was: %d",
        extensionValue.length);

    // Mask out unused bits (shouldn't be needed as they should already be 0).
    int unusedBitMask = 0xff;
    for (int i = 0; i < extensionValue[3]; i++) {
      unusedBitMask <<= 1;
    }
    extensionValue[extensionValue.length - 1] &= unusedBitMask;

    int transports = 0;
    for (int i = extensionValue.length - 1; i >= 5; i--) {
      byte b = extensionValue[i];
      for (int bi = 0; bi < 8; bi++) {
        transports = (transports << 1) | (b & 1);
        b >>= 1;
      }
    }

    return Optional.of(transports);
  }

  @Override
  public Attestation untrustedFromCertificate(X509Certificate attestationCertificate) {
    return Attestation.builder()
        .trusted(false)
        .transports(getTransports(attestationCertificate).map(Transport::fromInt))
        .build();
  }
}
