package demo.webauthn;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.RegistrationResult;
import java.time.Instant;
import lombok.Builder;
import lombok.Value;
import lombok.experimental.Wither;

@Value
@Builder
@Wither
public class CredentialRegistration extends JsonSerializable {

    String userHandleBase64;
    long signatureCount;

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
