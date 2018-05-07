package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.webauthn.data.RegistrationResult;
import com.yubico.webauthn.data.UserIdentity;
import demo.webauthn.json.ScalaJackson;
import java.time.Instant;
import lombok.Builder;
import lombok.Value;
import lombok.experimental.Wither;

@Value
@Builder
@Wither
public class CredentialRegistration extends JsonSerializable {

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

    @Override
    public String toJson() {
        return toJson(new ScalaJackson().get());
    }

}
