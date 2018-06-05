package demo.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import demo.webauthn.data.CredentialRegistration;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import scala.collection.immutable.Vector;

public interface RegistrationStorage extends CredentialRepository {

    boolean addRegistrationByUsername(String username, CredentialRegistration reg);

    Collection<CredentialRegistration> getRegistrationsByUsername(String username);
    Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, String idBase64);
    Collection<CredentialRegistration> getRegistrationsByUserHandle(String userHandleBase64);
    Optional<String> getUsername(String userHandleBase64);
    Optional<Vector<Object>> getUserHandle(String username);

    boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration);
    boolean removeAllRegistrations(String username);

    void updateSignatureCountForUsername(String username, String idBase64, long newSignatureCount);

}
