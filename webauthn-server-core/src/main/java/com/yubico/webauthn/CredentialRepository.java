package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.Optional;
import java.util.Set;


public interface CredentialRepository {

    Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username);

    Optional<ByteArray> getUserHandleForUsername(String username);

    Optional<String> getUsernameForUserHandle(ByteArray userHandleBase64);

    Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle);

    Set<RegisteredCredential> lookupAll(ByteArray credentialId);

}
