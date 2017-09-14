package demo.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.RegistrationResult;
import java.time.Instant;
import lombok.Value;

@Value
public class CredentialRegistration {

    String username;
    String credentialNickname;

    @JsonIgnore
    Instant registrationTime;
    RegistrationResult registration;

    @JsonProperty("registrationTime")
    public String getRegistrationTimestamp() {
        return registrationTime.toString();
    }

}
