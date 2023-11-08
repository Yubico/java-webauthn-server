package com.yubico.webauthn;

import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.Optional;
import java.util.Set;
import lombok.NonNull;

/**
 * @see <a href="https://w3c.github.io/webauthn/#credential-record">Credential Record</a>
 * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
 *     before reaching a mature release.
 */
@Deprecated
public interface CredentialRecord extends ToPublicKeyCredentialDescriptor {

  /**
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  @NonNull
  ByteArray getCredentialId();

  /**
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  @NonNull
  ByteArray getUserHandle();

  /**
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  @NonNull
  ByteArray getPublicKeyCose();

  /**
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  long getSignatureCount();

  /**
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  Optional<Set<AuthenticatorTransport>> getTransports();

  // boolean isUvInitialized();

  /**
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated
  Optional<Boolean> isBackupEligible();

  /**
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
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
}
