package com.yubico.webauthn;

import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserIdentity;
import java.util.Optional;
import java.util.Set;
import lombok.NonNull;

/**
 * An abstraction of properties of a stored WebAuthn credential.
 *
 * @see <a href="https://w3c.github.io/webauthn/#credential-record">Credential Record</a> in Web
 *     Authentication Level 3 (Editor's Draft)
 * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
 *     before reaching a mature release.
 */
@Deprecated
public interface CredentialRecord extends ToPublicKeyCredentialDescriptor {

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">credential
   * ID</a> of the credential.
   *
   * <p>Implementations MUST NOT return null.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">Credential
   *     ID</a>
   * @see RegistrationResult#getKeyId()
   * @see PublicKeyCredentialDescriptor#getId()
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  @NonNull
  ByteArray getCredentialId();

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">user handle</a>
   * of the user the credential is registered to.
   *
   * <p>Implementations MUST NOT return null.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">User Handle</a>
   * @see UserIdentity#getId()
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  @NonNull
  ByteArray getUserHandle();

  /**
   * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
   * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
   *
   * <p>This is used to verify the {@link AuthenticatorAssertionResponse#getSignature() signature}
   * in authentication assertions.
   *
   * <p>If your database has credentials encoded in U2F (raw) format, you may need to use {@link
   * #cosePublicKeyFromEs256Raw(ByteArray)} to convert them before returning them in this method.
   *
   * <p>Implementations MUST NOT return null.
   *
   * @see AttestedCredentialData#getCredentialPublicKey()
   * @see RegistrationResult#getPublicKeyCose()
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  @NonNull
  ByteArray getPublicKeyCose();

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
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  long getSignatureCount();

  /**
   * Transport hints as to how the client might communicate with the authenticator this credential
   * is bound to.
   *
   * <p>Implementations SHOULD return the value returned by {@link
   * AuthenticatorAttestationResponse#getTransports()} when the credential was created. That value
   * SHOULD NOT be modified.
   *
   * <p>Implementations MUST NOT return null.
   *
   * <p>This is used to set {@link PublicKeyCredentialDescriptor#getTransports()} in {@link
   * PublicKeyCredentialCreationOptions#getExcludeCredentials() excludeCredentials} in {@link
   * RelyingParty#startRegistration(StartRegistrationOptions)} and and {@link
   * PublicKeyCredentialRequestOptions#getAllowCredentials() allowCredentials} in {@link
   * RelyingParty#startAssertion(StartAssertionOptions)}.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-authenticatorattestationresponse-gettransports">getTransports()
   *     in 5.2.1. Information About Public Key Credential (interface
   *     AuthenticatorAttestationResponse)</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-publickeycredentialdescriptor-transports">transports
   *     in 5.8.3. Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
   * @see AuthenticatorAttestationResponse#getTransports()
   * @see PublicKeyCredentialDescriptor#getTransports()
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  Optional<Set<AuthenticatorTransport>> getTransports();

  // boolean isUvInitialized();

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
   * <p>{@link CredentialRecord} implementations SHOULD return the first known value returned by
   * {@link RegistrationResult#isBackupEligible()} or {@link AssertionResult#isBackupEligible()}, if
   * known. If unknown, {@link CredentialRecord} implementations SHOULD return <code>
   * Optional.empty()</code>.
   *
   * <p>Implementations MUST NOT return null.
   *
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release. EXPERIMENTAL: This feature is from a not yet mature
   *     standard; it could change as the standard matures.
   */
  @Deprecated
  Optional<Boolean> isBackupEligible();

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
   * <p>{@link CredentialRecord} implementations SHOULD return the most recent value returned by
   * {@link AssertionResult#isBackedUp()} or {@link RegistrationResult#isBackedUp()}, if known. If
   * unknown, {@link CredentialRecord} implementations SHOULD return <code>Optional.empty()</code>.
   *
   * <p>Implementations MUST NOT return null.
   *
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release. EXPERIMENTAL: This feature is from a not yet mature
   *     standard; it could change as the standard matures.
   */
  @Deprecated
  Optional<Boolean> isBackedUp();

  /**
   * This default implementation of {@link
   * ToPublicKeyCredentialDescriptor#toPublicKeyCredentialDescriptor()} sets the {@link
   * PublicKeyCredentialDescriptor.PublicKeyCredentialDescriptorBuilder#id(ByteArray) id} field to
   * the return value of {@link #getCredentialId()} and the {@link
   * PublicKeyCredentialDescriptor.PublicKeyCredentialDescriptorBuilder#transports(Optional)
   * transports} field to the return value of {@link #getTransports()}.
   *
   * @see <a
   *     href="https://w3c.github.io/webauthn/#credential-descriptor-for-a-credential-record">credential
   *     descriptor for a credential record</a> in Web Authentication Level 3 (Editor's Draft)
   */
  @Override
  default PublicKeyCredentialDescriptor toPublicKeyCredentialDescriptor() {
    return PublicKeyCredentialDescriptor.builder()
        .id(getCredentialId())
        .transports(getTransports())
        .build();
  }

  /**
   * Convert a credential public key from U2F format to COSE_Key format.
   *
   * <p>The U2F JavaScript API encoded credential public keys in <code>ALG_KEY_ECC_X962_RAW</code>
   * format as specified in <a
   * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats">FIDO
   * Registry §3.6.2 Public Key Representation Formats</a>. If your database has credential public
   * keys stored in this format, those public keys need to be converted to COSE_Key format before
   * they can be used by a {@link CredentialRecord} instance. This function performs the conversion.
   *
   * <p>If your application has only used the <code>navigator.credentials.create()</code> API to
   * register credentials, you likely do not need this function.
   *
   * @param es256RawKey a credential public key in <code>ALG_KEY_ECC_X962_RAW</code> format as
   *     specified in <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats">FIDO
   *     Registry §3.6.2 Public Key Representation Formats</a>.
   * @return a credential public key in COSE_Key format, suitable to be returned by {@link
   *     CredentialRecord#getPublicKeyCose()}.
   * @see RegisteredCredential.RegisteredCredentialBuilder#publicKeyEs256Raw(ByteArray)
   */
  static ByteArray cosePublicKeyFromEs256Raw(final ByteArray es256RawKey) {
    return WebAuthnCodecs.rawEcKeyToCose(es256RawKey);
  }
}
