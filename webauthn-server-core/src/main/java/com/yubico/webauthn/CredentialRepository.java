package com.yubico.webauthn;

import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RegisteredCredential;
import java.util.List;
import java.util.Optional;
import java.util.Set;


public interface CredentialRepository {

  List<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username);
  Optional<String> getUserHandleForUsername(String username);
  Optional<String> getUsernameForUserHandle(String userHandleBase64);
  Optional<RegisteredCredential> lookup(String credentialIdBase64, String userHandleBase64);
  Set<RegisteredCredential> lookupAll(String credentialIdBase64);

}
