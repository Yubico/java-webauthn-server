// Copyright (c) 2015-2018, Yubico AB
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

package com.yubico.webauthn.attestation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Non-standardized representation of partly free-form information about an authenticator device.
 */
@Value
@Builder(toBuilder = true)
public class Attestation implements Serializable {

  /**
   * <code>true</code> if and only if the contained information has been verified to be
   * cryptographically supported by a trusted attestation root.
   */
  private final boolean trusted;

  /** A unique identifier for a particular version of the data source of the data in this object. */
  private final String metadataIdentifier;

  /** Free-form information about the authenticator vendor. */
  private final Map<String, String> vendorProperties;

  /** Free-form information about the authenticator model. */
  private final Map<String, String> deviceProperties;

  /** The set of communication modes supported by the authenticator. */
  private final Set<Transport> transports;

  @JsonCreator
  private Attestation(
      @JsonProperty("trusted") boolean trusted,
      @JsonProperty("metadataIdentifier") String metadataIdentifier,
      @JsonProperty("vendorProperties") Map<String, String> vendorProperties,
      @JsonProperty("deviceProperties") Map<String, String> deviceProperties,
      @JsonProperty("transports") Set<Transport> transports) {
    this.trusted = trusted;
    this.metadataIdentifier = metadataIdentifier;
    this.vendorProperties = vendorProperties;
    this.deviceProperties = deviceProperties;
    this.transports = transports == null ? null : new TreeSet<>(transports);
  }

  /** A unique identifier for a particular version of the data source of the data in this object. */
  public Optional<String> getMetadataIdentifier() {
    return Optional.ofNullable(metadataIdentifier);
  }

  /** Free-form information about the authenticator vendor. */
  public Optional<Map<String, String>> getVendorProperties() {
    return Optional.ofNullable(vendorProperties);
  }

  /** Free-form information about the authenticator model. */
  public Optional<Map<String, String>> getDeviceProperties() {
    return Optional.ofNullable(deviceProperties);
  }

  /** The set of communication modes supported by the authenticator. */
  public Optional<Set<Transport>> getTransports() {
    return Optional.ofNullable(transports);
  }

  public static Attestation empty() {
    return builder().trusted(false).build();
  }

  public static AttestationBuilder.MandatoryStages builder() {
    return new AttestationBuilder.MandatoryStages();
  }

  public static class AttestationBuilder {
    private boolean trusted;
    private String metadataIdentifier;
    private Map<String, String> vendorProperties;
    private Map<String, String> deviceProperties;
    private Set<Transport> transports;

    public static class MandatoryStages {
      private final AttestationBuilder builder = new AttestationBuilder();

      /**
       * {@link AttestationBuilder#trusted(boolean) trusted} is a required parameter.
       *
       * @see AttestationBuilder#trusted(boolean)
       */
      public AttestationBuilder trusted(boolean trusted) {
        return builder.trusted(trusted);
      }
    }

    public AttestationBuilder metadataIdentifier(@NonNull Optional<String> metadataIdentifier) {
      return this.metadataIdentifier(metadataIdentifier.orElse(null));
    }

    public AttestationBuilder metadataIdentifier(String metadataIdentifier) {
      this.metadataIdentifier = metadataIdentifier;
      return this;
    }

    public AttestationBuilder vendorProperties(
        @NonNull Optional<Map<String, String>> vendorProperties) {
      return this.vendorProperties(vendorProperties.orElse(null));
    }

    public AttestationBuilder vendorProperties(Map<String, String> vendorProperties) {
      this.vendorProperties = vendorProperties;
      return this;
    }

    public AttestationBuilder deviceProperties(
        @NonNull Optional<Map<String, String>> deviceProperties) {
      return this.deviceProperties(deviceProperties.orElse(null));
    }

    public AttestationBuilder deviceProperties(Map<String, String> deviceProperties) {
      this.deviceProperties = deviceProperties;
      return this;
    }

    public AttestationBuilder transports(@NonNull Optional<Set<Transport>> transports) {
      return this.transports(transports.orElse(null));
    }

    public AttestationBuilder transports(Set<Transport> transports) {
      this.transports = transports;
      return this;
    }
  }
}
