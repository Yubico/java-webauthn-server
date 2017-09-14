package demo.webauthn;

import com.yubico.webauthn.RegistrationResult;
import java.time.Instant;
import lombok.Value;

@Value
public class CredentialRegistration {

    String username;
    String credentialNickname;
    Instant registrationTime;
    RegistrationResult registration;

}
