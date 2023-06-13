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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * An abstraction of a credential registered to a particular user.
 *
 * <p>Instances of this class are not expected to be long-lived, and the library only needs to read
 * them, never write them. You may at your discretion store them directly in your database, or
 * assemble them from other components.
 */
@Value
@Jacksonized
@Builder(toBuilder = true)
public final class RegisteredCredential {

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">credential
   * ID</a> of the credential.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">Credential
   *     ID</a>
   * @see RegistrationResult#getKeyId()
   * @see PublicKeyCredentialDescriptor#getId()
   */
  @NonNull private final ByteArray credentialId;

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">user handle</a>
   * of the user the credential is registered to.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">User Handle</a>
   * @see UserIdentity#getId()
   */
  @NonNull private final ByteArray userHandle;

  /**
   * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
   * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
   *
   * <p>This is used to verify the {@link AuthenticatorAssertionResponse#getSignature() signature}
   * in authentication assertions.
   *
   * @see AttestedCredentialData#getCredentialPublicKey()
   * @see RegistrationResult#getPublicKeyCose()
   */
  @NonNull private final ByteArray publicKeyCose;

  /**
   * The stored <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#signcount">signature
   * count</a> of the credential.
   *
   * <p>This is used to validate the {@link AuthenticatorData#getSignatureCounter() signature
   * counter} in authentication assertions.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">§6.1.
   *     Authenticator Data</a>
   * @see AuthenticatorData#getSignatureCounter()
   * @see AssertionResult#getSignatureCount()
   */
  @Builder.Default private final long signatureCount = 0;

  /**
   * The state of the <a href="https://w3c.github.io/webauthn/#authdata-flags-be">BE flag</a> when
   * this credential was registered, if known.
   *
   * <p>If absent, it is not known whether or not this credential is backup eligible.
   *
   * <p>If present and <code>true</code>, the credential is backup eligible: it can be backed up in
   * some way, most commonly by syncing the private key to a cloud account.
   *
   * <p>If present and <code>false</code>, the credential is not backup eligible: it cannot be
   * backed up in any way.
   *
   * <p>{@link CredentialRepository} implementations SHOULD set this to the first known value
   * returned by {@link RegistrationResult#isBackupEligible()} or {@link
   * AssertionResult#isBackupEligible()}, if known. If unknown, {@link CredentialRepository}
   * implementations SHOULD set this to <code>null</code> or not set this value.
   *
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @Getter(AccessLevel.NONE)
  @Builder.Default
  private final Boolean backupEligible = null;

  /**
   * The last known state of the <a href="https://w3c.github.io/webauthn/#authdata-flags-bs">BS
   * flag</a> for this credential, if known.
   *
   * <p>If absent, the backup state of the credential is not known.
   *
   * <p>If present and <code>true</code>, the credential is believed to be currently backed up.
   *
   * <p>If present and <code>false</code>, the credential is believed to not be currently backed up.
   *
   * <p>{@link CredentialRepository} implementations SHOULD set this to the most recent value
   * returned by {@link AssertionResult#isBackedUp()} or {@link RegistrationResult#isBackedUp()}, if
   * known. If unknown, {@link CredentialRepository} implementations SHOULD set this to <code>null
   * </code> or not set this value.
   *
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @Getter(AccessLevel.NONE)
  @Builder.Default
  private final Boolean backupState = null;

  /**
   * The state of the <a href="https://w3c.github.io/webauthn/#authdata-flags-be">BE flag</a> when
   * this credential was registered, if known.
   *
   * <p>If absent, it is not known whether or not this credential is backup eligible.
   *
   * <p>If present and <code>true</code>, the credential is backup eligible: it can be backed up in
   * some way, most commonly by syncing the private key to a cloud account.
   *
   * <p>If present and <code>false</code>, the credential is not backup eligible: it cannot be
   * backed up in any way.
   *
   * <p>{@link CredentialRepository} implementations SHOULD set this to the first known value
   * returned by {@link RegistrationResult#isBackupEligible()} or {@link
   * AssertionResult#isBackupEligible()}, if known. If unknown, {@link CredentialRepository}
   * implementations SHOULD set this to <code>null</code> or not set this value.
   *
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  public Optional<Boolean> isBackupEligible() {
    return Optional.ofNullable(backupEligible);
  }

  /**
   * The last known state of the <a href="https://w3c.github.io/webauthn/#authdata-flags-bs">BS
   * flag</a> for this credential, if known.
   *
   * <p>If absent, the backup state of the credential is not known.
   *
   * <p>If present and <code>true</code>, the credential is believed to be currently backed up.
   *
   * <p>If present and <code>false</code>, the credential is believed to not be currently backed up.
   *
   * <p>{@link CredentialRepository} implementations SHOULD set this to the most recent value
   * returned by {@link AssertionResult#isBackedUp()} or {@link RegistrationResult#isBackedUp()}, if
   * known. If unknown, {@link CredentialRepository} implementations SHOULD set this to <code>null
   * </code> or not set this value.
   *
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  public Optional<Boolean> isBackedUp() {
    return Optional.ofNullable(backupState);
  }

  /**
   * Opaque extra-data object provided by consumer code. The library will not access it in any way;
   * however, it can be extracted using {@link #getExtraData(Class)}.
   */
  @JsonIgnore
  @Getter(AccessLevel.NONE)
  @Builder.Default
  private final Object extraData = null;

  /**
   * Retrieves any extra data that was provided during building, unmodified.
   *
   * @param <T> The type of the stored extra data.
   * @param assertedType The type of the stored extra data; a ClassCastException results in an empty
   *     Optional.
   * @return The opaque extra data stored during building, unmodified.
   */
  public <T> Optional<T> getExtraData(Class<T> assertedType) {
    try {
      return Optional.ofNullable(extraData).map(assertedType::cast);
    } catch (ClassCastException ex) {
      return Optional.empty();
    }
  }

  public static RegisteredCredentialBuilder.MandatoryStages builder() {
    return new RegisteredCredentialBuilder.MandatoryStages();
  }

  public static class RegisteredCredentialBuilder {
    public static class MandatoryStages {
      private final RegisteredCredentialBuilder builder = new RegisteredCredentialBuilder();

      /**
       * {@link RegisteredCredentialBuilder#credentialId(ByteArray) credentialId} is a required
       * parameter.
       *
       * @see RegisteredCredentialBuilder#credentialId(ByteArray)
       */
      public Step2 credentialId(ByteArray credentialId) {
        builder.credentialId(credentialId);
        return new Step2();
      }

      public class Step2 {
        /**
         * {@link RegisteredCredentialBuilder#userHandle(ByteArray) userHandle} is a required
         * parameter.
         *
         * @see RegisteredCredentialBuilder#userHandle(ByteArray)
         */
        public Step3 userHandle(ByteArray userHandle) {
          builder.userHandle(userHandle);
          return new Step3();
        }
      }

      public class Step3 {
        /**
         * {@link RegisteredCredentialBuilder#publicKeyCose(ByteArray) publicKeyCose} is a required
         * parameter.
         *
         * <p>The return value of {@link RegistrationResult#getPublicKeyCose()} is a suitable
         * argument for this method.
         *
         * <p>Alternatively, the public key can be specified using the {@link
         * #publicKeyEs256Raw(ByteArray)} method if the key is stored in the U2F format (<code>
         * ALG_KEY_ECC_X962_RAW</code> as specified in <a
         * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats">FIDO
         * Registry §3.6.2 Public Key Representation Formats</a>). This is mostly useful for public
         * keys registered via the U2F JavaScript API.
         *
         * @see #publicKeyEs256Raw(ByteArray)
         * @see RegisteredCredentialBuilder#publicKeyCose(ByteArray)
         * @see <a
         *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats">FIDO
         *     Registry §3.6.2 Public Key Representation Formats</a>
         */
        public RegisteredCredentialBuilder publicKeyCose(ByteArray publicKeyCose) {
          return builder.publicKeyCose(publicKeyCose);
        }

        /**
         * Specify the credential public key in U2F format.
         *
         * <p>An alternative to {@link #publicKeyCose(ByteArray)}, this method expects an {@link
         * COSEAlgorithmIdentifier#ES256 ES256} public key in <code>ALG_KEY_ECC_X962_RAW</code>
         * format as specified in <a
         * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats">FIDO
         * Registry §3.6.2 Public Key Representation Formats</a>.
         *
         * <p>This is primarily intended for public keys registered via the U2F JavaScript API. If
         * your application has only used the <code>navigator.credentials.create()</code> API to
         * register credentials, you should use {@link #publicKeyCose(ByteArray)} instead.
         *
         * @see RegisteredCredentialBuilder#publicKeyCose(ByteArray)
         */
        public RegisteredCredentialBuilder publicKeyEs256Raw(ByteArray publicKeyEs256Raw) {
          return builder.publicKeyCose(WebAuthnCodecs.rawEcKeyToCose(publicKeyEs256Raw));
        }
      }
    }

    /**
     * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
     * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>. This method overwrites {@link
     * #publicKeyEs256Raw(ByteArray)}.
     *
     * <p>The return value of {@link RegistrationResult#getPublicKeyCose()} is a suitable argument
     * for this method.
     *
     * <p>This is used to verify the {@link AuthenticatorAssertionResponse#getSignature() signature}
     * in authentication assertions.
     *
     * <p>Alternatively, the public key can be specified using the {@link
     * #publicKeyEs256Raw(ByteArray)} method if the key is stored in the U2F format (<code>
     * ALG_KEY_ECC_X962_RAW</code> as specified in <a
     * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats">FIDO
     * Registry §3.6.2 Public Key Representation Formats</a>). This is mostly useful for public keys
     * registered via the U2F JavaScript API.
     *
     * @see AttestedCredentialData#getCredentialPublicKey()
     * @see RegistrationResult#getPublicKeyCose()
     */
    public RegisteredCredentialBuilder publicKeyCose(@NonNull ByteArray publicKeyCose) {
      this.publicKeyCose = publicKeyCose;
      return this;
    }

    /**
     * Specify the credential public key in U2F format. This method overwrites {@link
     * #publicKeyCose(ByteArray)}.
     *
     * <p>An alternative to {@link #publicKeyCose(ByteArray)}, this method expects an {@link
     * COSEAlgorithmIdentifier#ES256 ES256} public key in <code>ALG_KEY_ECC_X962_RAW</code> format
     * as specified in <a
     * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats">FIDO
     * Registry §3.6.2 Public Key Representation Formats</a>.
     *
     * <p>This is primarily intended for public keys registered via the U2F JavaScript API. If your
     * application has only used the <code>navigator.credentials.create()</code> API to register
     * credentials, you should use {@link #publicKeyCose(ByteArray)} instead.
     *
     * @see RegisteredCredentialBuilder#publicKeyCose(ByteArray)
     */
    public RegisteredCredentialBuilder publicKeyEs256Raw(ByteArray publicKeyEs256Raw) {
      return publicKeyCose(WebAuthnCodecs.rawEcKeyToCose(publicKeyEs256Raw));
    }
  }
}
