package demo.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InMemoryRegistrationStorage implements RegistrationStorage, CredentialRepository {

    private final Multimap<String, CredentialRegistration> storage = HashMultimap.create();
    private Logger logger = LoggerFactory.getLogger(InMemoryRegistrationStorage.class);

    @Override
    public boolean addRegistrationByUsername(String username, CredentialRegistration reg) {
        return storage.put(username, reg);
    }

    @Override
    public List<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return getRegistrationsByUsername(username).stream()
            .map(registration -> registration.getRegistration().keyId())
            .collect(Collectors.toList());
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUsername(String username) {
        return storage.get(username);
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUserHandle(String userHandleBase64) {
        return storage.values().stream()
            .filter(credentialRegistration ->
                userHandleBase64.equals(credentialRegistration.getUserHandleBase64())
            )
            .collect(Collectors.toList());
    }

    @Override
    public Optional<String> getUsername(String userHandleBase64) {
        return getRegistrationsByUserHandle(userHandleBase64).stream()
            .findAny()
            .map(CredentialRegistration::getUsername);
    }

    @Override
    public boolean usernameOwnsCredential(String username, String idBase64) {
        return storage.get(username).stream()
            .anyMatch(credentialRegistration ->
                idBase64.equals(credentialRegistration.getRegistration().keyId().idBase64())
            );
    }

    @Override
    public void updateSignatureCountForUsername(String username, String idBase64, long newSignatureCount) {
        CredentialRegistration registration = getRegistrationByUsernameAndCredentialId(username, idBase64)
            .orElseThrow(() -> new NoSuchElementException(String.format(
                "Credential \"%s\" is not registered to user \"%s\"",
                idBase64, username
            )));

        storage.remove(username, registration);
        storage.put(username, registration.withSignatureCount(newSignatureCount));
    }

    @Override
    public Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, String idBase64) {
        return storage.get(username).stream()
            .filter(credReg -> idBase64.equals(credReg.getRegistration().keyId().idBase64()))
            .findFirst();
    }

    @Override
    public boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration) {
        return storage.remove(username, credentialRegistration);
    }

    @Override
    public boolean userHandleOwnsCredential(String userHandleBase64, String idBase64) {
        return storage.values().stream()
            .filter(credentialRegistration ->
                userHandleBase64.equals(credentialRegistration.getUserHandleBase64())
            )
            .anyMatch(credentialRegistration ->
                idBase64.equals(credentialRegistration.getRegistration().keyId().idBase64())
            );
    }

    @Override
    public Optional<RegisteredCredential> lookup(String credentialId, Optional<String> userHandle) {
        Optional<CredentialRegistration> registrationMaybe = storage.values().stream()
            .filter(credReg -> credentialId.equals(credReg.getRegistration().keyId().idBase64()))
            .findAny();

        logger.debug("lookup credential ID: {}, user handle: {}; result: {}", credentialId, userHandle, registrationMaybe);
        return registrationMaybe.flatMap(registration -> {
            final byte[] cose = registration.getRegistration().publicKeyCose();
            final PublicKey key = WebAuthnCodecs.importCoseP256PublicKey(cose);

            if (key == null) {
                String coseString;
                try {
                    coseString = WebAuthnCodecs.json().writeValueAsString(cose);
                } catch (JsonProcessingException e) {
                    coseString = "(Failed to write as string)";
                }

                logger.error("Failed to decode public key in storage: ID: {} COSE: {}", credentialId, coseString);
                return Optional.empty();
            } else {
                return Optional.of(
                    new RegisteredCredential(
                        registration.getRegistration().keyId().id(),
                        key,
                        registration.getSignatureCount(),
                        U2fB64Encoding.decode(registration.getUserHandleBase64())
                    )
                );
            }
        });
    }

    @Override
    public scala.collection.immutable.Set<RegisteredCredential> lookupAll(String credentialId) {
        return scala.collection.JavaConverters.asScalaSetConverter(storage.values().stream()
            .filter(reg -> reg.getRegistration().keyId().idBase64().equals(credentialId))
            .collect(Collectors.toSet())).asScala().toSet();
    }

}
