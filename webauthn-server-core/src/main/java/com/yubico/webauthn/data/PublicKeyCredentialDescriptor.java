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

package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.internal.util.ComparableUtil;
import com.yubico.webauthn.RegistrationResult;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * The attributes that are specified by a caller when referring to a public key credential as an
 * input parameter to the <code>navigator.credentials.create()</code> or <code>
 * navigator.credentials.get()</code> methods. It mirrors the fields of the {@link
 * PublicKeyCredential} object returned by the latter methods.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialdescriptor">§5.10.3.
 *     Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
 */
@Value
@Builder(toBuilder = true)
public class PublicKeyCredentialDescriptor implements Comparable<PublicKeyCredentialDescriptor> {

  /** The type of the credential the caller is referring to. */
  @NonNull @Builder.Default
  private final PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;

  /** The credential ID of the public key credential the caller is referring to. */
  @NonNull private final ByteArray id;

  /**
   * An OPTIONAL hint as to how the client might communicate with the managing authenticator of the
   * public key credential the caller is referring to.
   *
   * <p>This SHOULD be stored along with the {@link #getId() id} and used unmodified whenever
   * creating a {@link PublicKeyCredentialDescriptor} for this credential.
   */
  private final SortedSet<AuthenticatorTransport> transports;

  @JsonCreator
  private PublicKeyCredentialDescriptor(
      @NonNull @JsonProperty("type") PublicKeyCredentialType type,
      @NonNull @JsonProperty("id") ByteArray id,
      @JsonProperty("transports") Set<AuthenticatorTransport> transports) {
    this.type = type;
    this.id = id;
    this.transports =
        transports == null ? null : CollectionUtil.immutableSortedSet(new TreeSet<>(transports));
  }

  @Override
  public int compareTo(PublicKeyCredentialDescriptor other) {
    int idComparison = id.compareTo(other.id);
    if (idComparison != 0) {
      return idComparison;
    }

    if (type.compareTo(other.type) != 0) {
      return type.compareTo(other.type);
    }

    if (!getTransports().isPresent() && other.getTransports().isPresent()) {
      return -1;
    } else if (getTransports().isPresent() && !other.getTransports().isPresent()) {
      return 1;
    } else if (getTransports().isPresent() && other.getTransports().isPresent()) {
      int transportsComparison =
          ComparableUtil.compareComparableSets(getTransports().get(), other.getTransports().get());
      if (transportsComparison != 0) {
        return transportsComparison;
      }
    }

    return 0;
  }

  public static PublicKeyCredentialDescriptorBuilder.MandatoryStages builder() {
    return new PublicKeyCredentialDescriptorBuilder.MandatoryStages();
  }

  public static class PublicKeyCredentialDescriptorBuilder {
    private Set<AuthenticatorTransport> transports = null;

    public static class MandatoryStages {
      private PublicKeyCredentialDescriptorBuilder builder =
          new PublicKeyCredentialDescriptorBuilder();

      /**
       * {@link PublicKeyCredentialDescriptorBuilder#id(ByteArray) id} is a required parameter.
       *
       * @see PublicKeyCredentialDescriptorBuilder#id(ByteArray)
       */
      public PublicKeyCredentialDescriptorBuilder id(ByteArray id) {
        return builder.id(id);
      }
    }

    /**
     * An OPTIONAL hint as to how the client might communicate with the managing authenticator of
     * the public key credential the caller is referring to.
     *
     * <p>This SHOULD be set to the unmodified value returned from {@link
     * RegistrationResult#getKeyId()}.{@link #getTransports()} when the credential was registered.
     */
    public PublicKeyCredentialDescriptorBuilder transports(
        @NonNull Optional<Set<AuthenticatorTransport>> transports) {
      return this.transports(transports.orElse(null));
    }

    /**
     * An OPTIONAL hint as to how the client might communicate with the managing authenticator of
     * the public key credential the caller is referring to.
     *
     * <p>This SHOULD be set to the unmodified value returned from {@link
     * RegistrationResult#getKeyId()}.{@link #getTransports()} when the credential was registered.
     */
    public PublicKeyCredentialDescriptorBuilder transports(Set<AuthenticatorTransport> transports) {
      this.transports = transports;
      return this;
    }
  }

  public Optional<SortedSet<AuthenticatorTransport>> getTransports() {
    return Optional.ofNullable(transports);
  }
}
