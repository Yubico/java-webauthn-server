package com.yubico.example;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.util.Optional;
import java.util.Set;

public class Example {

    public RelyingParty getRp() {
        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder()
                        .id("localhost")
                        .name("Example RP")
                        .build())
                .credentialRepository(new CredentialRepository() {
                    @Override public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) { return null; }
                    @Override public Optional<ByteArray> getUserHandleForUsername(String username) { return Optional.empty(); }
                    @Override public Optional<String> getUsernameForUserHandle(ByteArray userHandle) { return Optional.empty(); }
                    @Override public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) { return Optional.empty(); }
                    @Override public Set<RegisteredCredential> lookupAll(ByteArray credentialId) { return null; }
                })
            .build();
    }

}
