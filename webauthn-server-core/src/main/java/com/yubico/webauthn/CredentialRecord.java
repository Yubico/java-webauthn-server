package com.yubico.webauthn;

import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import java.util.Optional;
import java.util.Set;
import lombok.NonNull;

/**
 * @see <a href="https://w3c.github.io/webauthn/#credential-record">Credential Record</a>
 * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
 *     before reaching a mature release.
 */
@Deprecated
public interface CredentialRecord {

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
  @NonNull
  default Optional<Set<AuthenticatorTransport>> getTransports() {
    return Optional.empty();
  }

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
}
