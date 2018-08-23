package demo.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.AssertionResult;
import com.yubico.util.ByteArray;
import demo.webauthn.data.CredentialRegistration;
import java.util.Collection;
import java.util.Optional;

public interface RegistrationStorage extends CredentialRepository {

    boolean addRegistrationByUsername(String username, CredentialRegistration reg);

    Collection<CredentialRegistration> getRegistrationsByUsername(String username);
    Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, ByteArray userHandle);
    Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle);

    boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration);
    boolean removeAllRegistrations(String username);

    void updateSignatureCount(AssertionResult result);

}
