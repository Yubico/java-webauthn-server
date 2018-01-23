package demo.webauthn;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.stream.Collectors;

public class InMemoryRegistrationStorage implements RegistrationStorage {

    private final Multimap<String, CredentialRegistration> storage = HashMultimap.create();

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

}
