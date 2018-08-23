package com.yubico.webauthn;

import com.yubico.util.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RegisteredCredential;
import java.util.List;
import java.util.Optional;
import java.util.Set;


public interface CredentialRepository {

    List<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username);

    Optional<ByteArray> getUserHandleForUsername(String username);

    Optional<String> getUsernameForUserHandle(ByteArray userHandleBase64);

    Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle);

    Set<RegisteredCredential> lookupAll(ByteArray credentialId);

}
