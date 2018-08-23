package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.RegistrationResult;
import com.yubico.webauthn.data.UserIdentity;
import java.time.Instant;
import lombok.Builder;
import lombok.Value;
import lombok.experimental.Wither;

@Value
@Builder
@Wither
public class CredentialRegistration {

    long signatureCount;

    String username;
    UserIdentity userIdentity;
    String credentialNickname;

    @JsonIgnore
    Instant registrationTime;
    RegistrationResult registration;

    @JsonProperty("registrationTime")
    public String getRegistrationTimestamp() {
        return registrationTime.toString();
    }

}
