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
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.CollectionUtil;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

/**
 * Contains <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-extension-output">authenticator
 * extension outputs</a> from a <code>navigator.credentials.create()</code> operation.
 *
 * <p>Note that there is no guarantee that any extension input present in {@link
 * RegistrationExtensionInputs} will have a corresponding output present here.
 *
 * <p>The values contained here are parsed from the {@link AuthenticatorData} structure.
 *
 * <p>The client extension outputs are represented by the {@link ClientRegistrationExtensionOutputs}
 * type.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-extensions">§9. WebAuthn
 *     Extensions</a>
 */
@Value
@Builder(toBuilder = true)
@Slf4j
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuthenticatorRegistrationExtensionOutputs
    implements AuthenticatorExtensionOutputs {

  private final List<Extensions.Uvm.UvmEntry> uvm;

  @JsonCreator
  private AuthenticatorRegistrationExtensionOutputs(
      @JsonProperty("uvm") List<Extensions.Uvm.UvmEntry> uvm) {
    this.uvm = uvm == null ? null : CollectionUtil.immutableList(uvm);
  }

  /**
   * Parse <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#registration-extension">registration</a>
   * <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-extension-output">authenticator
   * extension outputs</a> from the given authenticator data.
   *
   * <p>If the <code>authData</code> does not contain authenticator extension outputs, this returns
   * an empty {@link Optional}.
   *
   * <p>Otherwise, this returns a present {@link Optional} containing an {@link
   * AuthenticatorRegistrationExtensionOutputs} value with all validly-formatted <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#registration-extension">registration</a>
   * <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-extension-output">extension
   * outputs</a> supported by this library. This silently ignores <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authentication-extension">authentication</a>
   * extension outputs, malformed extension outputs, and unsupported extensions. The raw set of
   * extension outputs can instead be obtained via {@link AuthenticatorData#getExtensions()}.
   *
   * <p>Note that a present {@link AuthenticatorRegistrationExtensionOutputs} may contain zero
   * extension outputs.
   *
   * @param authData the <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-data">authenticator
   *     data</a> to parse extension outputs from
   * @return an empty {@link Optional} if the <code>authData</code> does not contain authenticator
   *     extension outputs. Otherwise a present {@link Optional} containing parsed extension output
   *     values.
   */
  public static Optional<AuthenticatorRegistrationExtensionOutputs> fromAuthenticatorData(
      AuthenticatorData authData) {
    return authData.getExtensions().flatMap(AuthenticatorRegistrationExtensionOutputs::fromCbor);
  }

  static Optional<AuthenticatorRegistrationExtensionOutputs> fromCbor(CBORObject cbor) {
    AuthenticatorRegistrationExtensionOutputsBuilder b = builder();

    Extensions.Uvm.parseAuthenticatorExtensionOutput(cbor).ifPresent(b::uvm);

    AuthenticatorRegistrationExtensionOutputs result = b.build();

    if (result.getExtensionIds().isEmpty()) {
      return Optional.empty();
    } else {
      return Optional.of(result);
    }
  }

  @Override
  @EqualsAndHashCode.Include
  public Set<String> getExtensionIds() {
    HashSet<String> ids = new HashSet<>();
    if (uvm != null) {
      ids.add(Extensions.Uvm.EXTENSION_ID);
    }
    return ids;
  }

  /**
   * @return The <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-extension-output">authenticator
   *     extension output</a> for the <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">User
   *     Verification Method (<code>uvm</code>) extension</a>, if any.
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
   *     User Verification Method extension (uvm)</a>
   */
  public Optional<List<Extensions.Uvm.UvmEntry>> getUvm() {
    return Optional.ofNullable(uvm);
  }
}
