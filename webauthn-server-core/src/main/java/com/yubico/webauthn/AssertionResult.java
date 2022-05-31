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

package com.yubico.webauthn;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.data.AuthenticatorAssertionExtensionOutputs;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserIdentity;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/** The result of a call to {@link RelyingParty#finishAssertion(FinishAssertionOptions)}. */
@Value
@Builder(toBuilder = true)
public class AssertionResult {

  /** <code>true</code> if the assertion was verified successfully. */
  private final boolean success;

  /**
   * The {@link RegisteredCredential} that was returned by {@link
   * CredentialRepository#lookup(ByteArray, ByteArray)} and whose public key was used to
   * successfully verify the assertion signature.
   *
   * <p>NOTE: The {@link RegisteredCredential#getSignatureCount() signature count} in this object
   * will reflect the signature counter state <i>before</i> the assertion operation, not the new
   * counter value. When updating your database state, use the signature counter from {@link
   * #getSignatureCount()} instead.
   */
  private final RegisteredCredential credential;

  /**
   * The username of the authenticated user.
   *
   * @see #getUserHandle()
   */
  @NonNull private final String username;

  /**
   * The new <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#signcount">signature
   * count</a> of the credential used for the assertion.
   *
   * <p>You should update this value in your database.
   *
   * @see AuthenticatorData#getSignatureCounter()
   */
  private final long signatureCount;

  /**
   * <code>true</code> if and only if at least one of the following is true:
   *
   * <ul>
   *   <li>The {@link AuthenticatorData#getSignatureCounter() signature counter value} in the
   *       assertion was strictly greater than {@link RegisteredCredential#getSignatureCount() the
   *       stored one}.
   *   <li>The {@link AuthenticatorData#getSignatureCounter() signature counter value} in the
   *       assertion and {@link RegisteredCredential#getSignatureCount() the stored one} were both
   *       zero.
   * </ul>
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">§6.1.
   *     Authenticator Data</a>
   * @see AuthenticatorData#getSignatureCounter()
   * @see RegisteredCredential#getSignatureCount()
   * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#validateSignatureCounter(boolean)
   */
  private final boolean signatureCounterValid;

  private final ClientAssertionExtensionOutputs clientExtensionOutputs;

  private final AuthenticatorAssertionExtensionOutputs authenticatorExtensionOutputs;

  private AssertionResult(
      boolean success,
      @NonNull @JsonProperty("credential") RegisteredCredential credential,
      @NonNull String username,
      long signatureCount,
      boolean signatureCounterValid,
      ClientAssertionExtensionOutputs clientExtensionOutputs,
      AuthenticatorAssertionExtensionOutputs authenticatorExtensionOutputs) {
    this(
        success,
        credential,
        username,
        null,
        null,
        signatureCount,
        signatureCounterValid,
        clientExtensionOutputs,
        authenticatorExtensionOutputs);
  }

  @JsonCreator
  private AssertionResult(
      @JsonProperty("success") boolean success,
      @NonNull @JsonProperty("credential") RegisteredCredential credential,
      @NonNull @JsonProperty("username") String username,
      @JsonProperty("credentialId") ByteArray credentialId, // TODO: Delete in next major release
      @JsonProperty("userHandle") ByteArray userHandle, // TODO: Delete in next major release
      @JsonProperty("signatureCount") long signatureCount,
      @JsonProperty("signatureCounterValid") boolean signatureCounterValid,
      @JsonProperty("clientExtensionOutputs")
          ClientAssertionExtensionOutputs clientExtensionOutputs,
      @JsonProperty("authenticatorExtensionOutputs")
          AuthenticatorAssertionExtensionOutputs authenticatorExtensionOutputs) {
    this.success = success;
    this.credential = credential;
    this.username = username;

    if (credentialId != null) {
      ExceptionUtil.assure(
          credential.getCredentialId().equals(credentialId),
          "Legacy credentialId is present and does not equal credential.credentialId");
    }
    if (userHandle != null) {
      ExceptionUtil.assure(
          credential.getUserHandle().equals(userHandle),
          "Legacy userHandle is present and does not equal credential.userHandle");
    }

    this.signatureCount = signatureCount;
    this.signatureCounterValid = signatureCounterValid;
    this.clientExtensionOutputs =
        clientExtensionOutputs == null || clientExtensionOutputs.getExtensionIds().isEmpty()
            ? null
            : clientExtensionOutputs;
    this.authenticatorExtensionOutputs = authenticatorExtensionOutputs;
  }

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">credential
   * ID</a> of the credential used for the assertion.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">Credential
   *     ID</a>
   * @see PublicKeyCredentialRequestOptions#getAllowCredentials()
   * @deprecated Use {@link #getCredential()}.{@link RegisteredCredential#getCredentialId()
   *     getCredentialId()} instead.
   */
  @Deprecated
  public ByteArray getCredentialId() {
    return credential.getCredentialId();
  }

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">user handle</a>
   * of the authenticated user.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">User Handle</a>
   * @see UserIdentity#getId()
   * @see #getUsername()
   * @deprecated Use {@link #getCredential()}.{@link RegisteredCredential#getUserHandle()} ()
   *     getUserHandle()} instead.
   */
  @Deprecated
  public ByteArray getUserHandle() {
    return credential.getUserHandle();
  }

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-extension-output">client
   * extension outputs</a>, if any.
   *
   * <p>This is present if and only if at least one extension output is present in the return value.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-client-extension-processing">§9.4.
   *     Client Extension Processing</a>
   * @see ClientAssertionExtensionOutputs
   * @see #getAuthenticatorExtensionOutputs() ()
   */
  public Optional<ClientAssertionExtensionOutputs> getClientExtensionOutputs() {
    return Optional.ofNullable(clientExtensionOutputs);
  }

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-extension-output">authenticator
   * extension outputs</a>, if any.
   *
   * <p>This is present if and only if at least one extension output is present in the return value.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-extension-processing">§9.5.
   *     Authenticator Extension Processing</a>
   * @see AuthenticatorAssertionExtensionOutputs
   * @see #getClientExtensionOutputs()
   */
  public Optional<AuthenticatorAssertionExtensionOutputs> getAuthenticatorExtensionOutputs() {
    return Optional.ofNullable(authenticatorExtensionOutputs);
  }

  static AssertionResultBuilder.MandatoryStages builder() {
    return new AssertionResultBuilder.MandatoryStages();
  }

  static class AssertionResultBuilder {
    public static class MandatoryStages {
      private final AssertionResultBuilder builder = new AssertionResultBuilder();

      public Step2 success(boolean success) {
        builder.success(success);
        return new Step2();
      }

      public class Step2 {
        public Step3 credential(RegisteredCredential credential) {
          builder.credential(credential);
          return new Step3();
        }
      }

      public class Step3 {
        public Step4 username(String username) {
          builder.username(username);
          return new Step4();
        }
      }

      public class Step4 {
        public Step5 signatureCount(long signatureCount) {
          builder.signatureCount(signatureCount);
          return new Step5();
        }
      }

      public class Step5 {
        public Step6 signatureCounterValid(boolean signatureCounterValid) {
          builder.signatureCounterValid(signatureCounterValid);
          return new Step6();
        }
      }

      public class Step6 {
        public Step7 clientExtensionOutputs(
            ClientAssertionExtensionOutputs clientExtensionOutputs) {
          builder.clientExtensionOutputs(clientExtensionOutputs);
          return new Step7();
        }
      }

      public class Step7 {
        public AssertionResultBuilder assertionExtensionOutputs(
            AuthenticatorAssertionExtensionOutputs authenticatorExtensionOutputs) {
          return builder.authenticatorExtensionOutputs(authenticatorExtensionOutputs);
        }
      }
    }
  }
}
