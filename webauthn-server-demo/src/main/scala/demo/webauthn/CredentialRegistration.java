package demo.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.webauthn.RegistrationResult;
import java.time.Instant;
import lombok.Value;

@Value
public class CredentialRegistration extends JsonSerializable {

    String username;
    String credentialNickname;

    @JsonIgnore
    Instant registrationTime;
    RegistrationResult registration;

    @JsonProperty("registrationTime")
    public String getRegistrationTimestamp() {
        return registrationTime.toString();
    }

    @Override
    public String toJson() {
        return toJson(new ScalaJackson().get());
    }

}
