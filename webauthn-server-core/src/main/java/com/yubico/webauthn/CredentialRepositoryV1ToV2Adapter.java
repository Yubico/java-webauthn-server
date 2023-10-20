package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import lombok.AllArgsConstructor;

@AllArgsConstructor
class CredentialRepositoryV1ToV2Adapter
    implements CredentialRepositoryV2<RegisteredCredential>, UsernameRepository {

  private final CredentialRepository inner;

  @Override
  public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUserHandle(ByteArray userHandle) {
    return inner
        .getUsernameForUserHandle(userHandle)
        .map(inner::getCredentialIdsForUsername)
        .orElseGet(Collections::emptySet);
  }

  @Override
  public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
    return inner.lookup(credentialId, userHandle);
  }

  @Override
  public boolean credentialIdExists(ByteArray credentialId) {
    return !inner.lookupAll(credentialId).isEmpty();
  }

  @Override
  public Optional<ByteArray> getUserHandleForUsername(String username) {
    return inner.getUserHandleForUsername(username);
  }
}
