package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import java.util.Optional;
import lombok.NonNull;

/**
 * @see <a href="https://w3c.github.io/webauthn/#credential-record">Credential Record</a>
 */
public interface CredentialRecord {

  @NonNull
  ByteArray getCredentialId();

  @NonNull
  ByteArray getUserHandle();

  @NonNull
  ByteArray getPublicKeyCose();

  long getSignatureCount();

  // @NonNull
  // Set<AuthenticatorTransport> getTransports();

  // boolean isUvInitialized();

  Optional<Boolean> isBackupEligible();

  Optional<Boolean> isBackedUp();
}
