package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.util.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
public class RegistrationResponse {

    private final ByteArray requestId;

    private final PublicKeyCredential<AuthenticatorAttestationResponse> credential;

    @JsonCreator
    public RegistrationResponse(
        @JsonProperty("requestId") ByteArray requestId,
        @JsonProperty("credential") PublicKeyCredential<AuthenticatorAttestationResponse> credential
    ) {
        this.requestId = requestId;
        this.credential = credential;
    }

}
