package demo.webauthn;

import com.yubico.webauthn.RegistrationResult;
import lombok.Value;

@Value
public class CredentialRegistration {

    String username;
    RegistrationResult registration;

}
