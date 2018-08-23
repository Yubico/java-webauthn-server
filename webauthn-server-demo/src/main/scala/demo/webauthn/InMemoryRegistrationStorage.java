package demo.webauthn;

import COSE.CoseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.AssertionResult;
import com.yubico.webauthn.data.RegisteredCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.util.BinaryUtil;
import com.yubico.webauthn.util.WebAuthnCodecs;
import demo.webauthn.data.CredentialRegistration;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.collection.immutable.Vector;

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
    public List<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return getRegistrationsByUsername(username).stream()
            .map(registration -> registration.getRegistration().getKeyId())
            .collect(Collectors.toList());
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
    public Collection<CredentialRegistration> getRegistrationsByUserHandle(String userHandleBase64) {
        return storage.asMap().values().stream()
            .flatMap(Collection::stream)
            .filter(credentialRegistration ->
                userHandleBase64.equals(credentialRegistration.getUserIdentity().getIdBase64())
            )
            .collect(Collectors.toList());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(String userHandleBase64) {
        return getRegistrationsByUserHandle(userHandleBase64).stream()
            .findAny()
            .map(CredentialRegistration::getUsername);
    }

    @Override
    public Optional<String> getUserHandleForUsername(String username) {
        return getRegistrationsByUsername(username).stream()
            .findAny()
            .map(reg -> reg.getUserIdentity().getIdBase64());
    }

    @Override
    public void updateSignatureCount(AssertionResult result) {
        CredentialRegistration registration = getRegistrationByUsernameAndCredentialId(result.getUsername(), result.getCredentialIdBase64())
            .orElseThrow(() -> new NoSuchElementException(String.format(
                "Credential \"%s\" is not registered to user \"%s\"",
                result.getCredentialIdBase64(), result.getUsername()
            )));

        Set<CredentialRegistration> regs = storage.getIfPresent(result.getUsername());
        regs.remove(registration);
        regs.add(registration.withSignatureCount(result.getSignatureCount()));
    }

    @Override
    public Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, String idBase64) {
        try {
            return storage.get(username, HashSet::new).stream()
                .filter(credReg -> idBase64.equals(credReg.getRegistration().getKeyId().getIdBase64()))
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
    public Optional<RegisteredCredential> lookup(String credentialId, String userHandle) {
        Optional<CredentialRegistration> registrationMaybe = storage.asMap().values().stream()
            .flatMap(Collection::stream)
            .filter(credReg -> credentialId.equals(credReg.getRegistration().getKeyId().getIdBase64()))
            .findAny();

        logger.debug("lookup credential ID: {}, user handle: {}; result: {}", credentialId, userHandle, registrationMaybe);
        return registrationMaybe.flatMap(registration -> {
            final byte[] cose = registration.getRegistration().getPublicKeyCose();
            final PublicKey key;

            try {
                key = WebAuthnCodecs.importCoseP256PublicKey(cose);
            } catch (CoseException | IOException e) {
                String coseString;
                try {
                    coseString = WebAuthnCodecs.json().writeValueAsString(cose);
                } catch (JsonProcessingException e2) {
                    coseString = "(Failed to write as string)";
                }

                logger.error("Failed to decode public key in storage: ID: {} COSE: {}", credentialId, coseString);
                return Optional.empty();
            }

            try {
                return Optional.of(
                    new RegisteredCredential(
                        registration.getRegistration().getKeyId().getId(),
                        U2fB64Encoding.decode(registration.getUserIdentity().getIdBase64()),
                        key,
                        registration.getSignatureCount()
                    )
                );
            } catch (U2fBadInputException e) {
                logger.error("Failed to base64decode user handle: {}", registration.getUserIdentity().getIdBase64(), e);
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public Set<RegisteredCredential> lookupAll(String credentialId) {
        return Collections.unmodifiableSet(
            storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(reg -> reg.getRegistration().getKeyId().getIdBase64().equals(credentialId))
                .map(reg -> {
                    try {
                        return new RegisteredCredential(
                            reg.getRegistration().getKeyId().getId(),
                            reg.getUserIdentity().getId(),
                            WebAuthnCodecs.importCoseP256PublicKey(reg.getRegistration().getPublicKeyCose()),
                            reg.getSignatureCount()
                        );
                    } catch (CoseException | IOException e) {
                        log.error("Failed to read public key {} from storage", reg.getRegistration().getKeyId().getIdBase64(), e);
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toSet()));
    }

}
