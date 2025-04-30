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

package demo.webauthn;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import demo.webauthn.data.CredentialRegistration;
import java.util.Collection;
import java.util.HashSet;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InMemoryRegistrationStorage implements CredentialRepository {

  private final Cache<String, Set<CredentialRegistration>> storage =
      CacheBuilder.newBuilder().maximumSize(1000).expireAfterAccess(1, TimeUnit.DAYS).build();

  private static final Logger logger = LoggerFactory.getLogger(InMemoryRegistrationStorage.class);

  ////////////////////////////////////////////////////////////////////////////////
  // The following methods are required by the CredentialRepository interface.
  ////////////////////////////////////////////////////////////////////////////////

  @Override
  public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
    return getRegistrationsByUsername(username).stream()
        .map(
            registration ->
                PublicKeyCredentialDescriptor.builder()
                    .id(registration.getCredential().getCredentialId())
                    .transports(registration.getTransports())
                    .build())
        .collect(Collectors.toSet());
  }

  @Override
  public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
    return getRegistrationsByUserHandle(userHandle).stream()
        .findAny()
        .map(CredentialRegistration::getUsername);
  }

  @Override
  public Optional<ByteArray> getUserHandleForUsername(String username) {
    return getRegistrationsByUsername(username).stream()
        .findAny()
        .map(reg -> reg.getUserIdentity().getId());
  }

  @Override
  public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
    Optional<CredentialRegistration> registrationMaybe =
        storage.asMap().values().stream()
            .flatMap(Collection::stream)
            .filter(credReg -> credentialId.equals(credReg.getCredential().getCredentialId()))
            .findAny();

    logger.debug(
        "lookup credential ID: {}, user handle: {}; result: {}",
        credentialId,
        userHandle,
        registrationMaybe);
    return registrationMaybe.map(
        registration ->
            RegisteredCredential.builder()
                .credentialId(registration.getCredential().getCredentialId())
                .userHandle(registration.getUserIdentity().getId())
                .publicKeyCose(registration.getCredential().getPublicKeyCose())
                .signatureCount(registration.getCredential().getSignatureCount())
                .build());
  }

  @Override
  public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
    return CollectionUtil.immutableSet(
        storage.asMap().values().stream()
            .flatMap(Collection::stream)
            .filter(reg -> reg.getCredential().getCredentialId().equals(credentialId))
            .map(
                reg ->
                    RegisteredCredential.builder()
                        .credentialId(reg.getCredential().getCredentialId())
                        .userHandle(reg.getUserIdentity().getId())
                        .publicKeyCose(reg.getCredential().getPublicKeyCose())
                        .signatureCount(reg.getCredential().getSignatureCount())
                        .build())
            .collect(Collectors.toSet()));
  }

  ////////////////////////////////////////////////////////////////////////////////
  // The following methods are specific to this demo application.
  ////////////////////////////////////////////////////////////////////////////////

  public boolean addRegistrationByUsername(String username, CredentialRegistration reg) {
    try {
      return storage.get(username, HashSet::new).add(reg);
    } catch (ExecutionException e) {
      logger.error("Failed to add registration", e);
      throw new RuntimeException(e);
    }
  }

  public Collection<CredentialRegistration> getRegistrationsByUsername(String username) {
    try {
      return storage.get(username, HashSet::new);
    } catch (ExecutionException e) {
      logger.error("Registration lookup failed", e);
      throw new RuntimeException(e);
    }
  }

  public Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle) {
    return storage.asMap().values().stream()
        .flatMap(Collection::stream)
        .filter(
            credentialRegistration ->
                userHandle.equals(credentialRegistration.getUserIdentity().getId()))
        .collect(Collectors.toList());
  }

  public void updateSignatureCount(AssertionResult result) {
    CredentialRegistration registration =
        getRegistrationByUsernameAndCredentialId(
                result.getUsername(), result.getCredential().getCredentialId())
            .orElseThrow(
                () ->
                    new NoSuchElementException(
                        String.format(
                            "Credential \"%s\" is not registered to user \"%s\"",
                            result.getCredential().getCredentialId(), result.getUsername())));

    Set<CredentialRegistration> regs = storage.getIfPresent(result.getUsername());
    regs.remove(registration);
    regs.add(
        registration.withCredential(
            registration.getCredential().toBuilder()
                .signatureCount(result.getSignatureCount())
                .build()));
  }

  public Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(
      String username, ByteArray id) {
    try {
      return storage.get(username, HashSet::new).stream()
          .filter(credReg -> id.equals(credReg.getCredential().getCredentialId()))
          .findFirst();
    } catch (ExecutionException e) {
      logger.error("Registration lookup failed", e);
      throw new RuntimeException(e);
    }
  }

  public boolean removeRegistrationByUsername(
      String username, CredentialRegistration credentialRegistration) {
    try {
      return storage.get(username, HashSet::new).remove(credentialRegistration);
    } catch (ExecutionException e) {
      logger.error("Failed to remove registration", e);
      throw new RuntimeException(e);
    }
  }

  public boolean removeAllRegistrations(String username) {
    storage.invalidate(username);
    return true;
  }

  public boolean userExists(String username) {
    return !getRegistrationsByUsername(username).isEmpty();
  }
}
