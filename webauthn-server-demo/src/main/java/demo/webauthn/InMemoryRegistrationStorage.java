package demo.webauthn;

import COSE.CoseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.AssertionResult;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RegisteredCredential;
import com.yubico.webauthn.impl.WebAuthnCodecs;
import demo.webauthn.data.CredentialRegistration;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Slf4j
public class InMemoryRegistrationStorage implements RegistrationStorage, CredentialRepository {

    private final Cache<String, Set<CredentialRegistration>> storage = CacheBuilder.newBuilder()
        .maximumSize(1000)
        .expireAfterAccess(1, TimeUnit.DAYS)
        .build();

    private Logger logger = LoggerFactory.getLogger(InMemoryRegistrationStorage.class);

    @Override
    public boolean addRegistrationByUsername(String username, CredentialRegistration reg) {
        try {
            return storage.get(username, HashSet::new).add(reg);
        } catch (ExecutionException e) {
            logger.error("Failed to add registration", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return getRegistrationsByUsername(username).stream()
            .map(registration -> registration.getRegistration().getKeyId())
            .collect(Collectors.toSet());
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUsername(String username) {
        try {
            return storage.get(username, HashSet::new);
        } catch (ExecutionException e) {
            logger.error("Registration lookup failed", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle) {
        return storage.asMap().values().stream()
            .flatMap(Collection::stream)
            .filter(credentialRegistration ->
                userHandle.equals(credentialRegistration.getUserIdentity().getId())
            )
            .collect(Collectors.toList());
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
    public void updateSignatureCount(AssertionResult result) {
        CredentialRegistration registration = getRegistrationByUsernameAndCredentialId(result.getUsername(), result.getCredentialId())
            .orElseThrow(() -> new NoSuchElementException(String.format(
                "Credential \"%s\" is not registered to user \"%s\"",
                result.getCredentialId(), result.getUsername()
            )));

        Set<CredentialRegistration> regs = storage.getIfPresent(result.getUsername());
        regs.remove(registration);
        regs.add(registration.withSignatureCount(result.getSignatureCount()));
    }

    @Override
    public Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, ByteArray id) {
        try {
            return storage.get(username, HashSet::new).stream()
                .filter(credReg -> id.equals(credReg.getRegistration().getKeyId().getId()))
                .findFirst();
        } catch (ExecutionException e) {
            logger.error("Registration lookup failed", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration) {
        try {
            return storage.get(username, HashSet::new).remove(credentialRegistration);
        } catch (ExecutionException e) {
            logger.error("Failed to remove registration", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean removeAllRegistrations(String username) {
        storage.invalidate(username);
        return true;
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Optional<CredentialRegistration> registrationMaybe = storage.asMap().values().stream()
            .flatMap(Collection::stream)
            .filter(credReg -> credentialId.equals(credReg.getRegistration().getKeyId().getId()))
            .findAny();

        logger.debug("lookup credential ID: {}, user handle: {}; result: {}", credentialId, userHandle, registrationMaybe);
        return registrationMaybe.flatMap(registration -> {
            final ByteArray cose = registration.getRegistration().getPublicKeyCose();
            final PublicKey key;

            try {
                key = WebAuthnCodecs.importCoseP256PublicKey(cose);
            } catch (CoseException | IOException e) {
                String coseString;
                try {
                    coseString = WebAuthnCodecs.json().writeValueAsString(cose.getBytes());
                } catch (JsonProcessingException e2) {
                    coseString = "(Failed to write as string)";
                }

                logger.error("Failed to decode public key in storage: ID: {} COSE: {}", credentialId, coseString);
                return Optional.empty();
            }

            return Optional.of(
                RegisteredCredential.builder()
                    .credentialId(registration.getRegistration().getKeyId().getId())
                    .userHandle(registration.getUserIdentity().getId())
                    .publicKey(key)
                    .signatureCount(registration.getSignatureCount())
                    .build()
            );
        });
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return Collections.unmodifiableSet(
            storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(reg -> reg.getRegistration().getKeyId().getId().equals(credentialId))
                .map(reg -> {
                    try {
                        return RegisteredCredential.builder()
                            .credentialId(reg.getRegistration().getKeyId().getId())
                            .userHandle(reg.getUserIdentity().getId())
                            .publicKey(WebAuthnCodecs.importCoseP256PublicKey(reg.getRegistration().getPublicKeyCose()))
                            .signatureCount(reg.getSignatureCount())
                            .build();
                    } catch (CoseException | IOException e) {
                        log.error("Failed to read public key {} from storage", reg.getRegistration().getKeyId().getId(), e);
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toSet()));
    }

}
