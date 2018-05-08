package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Value;

@Value
public class RegistrationResponse {

    String requestId;

    @JsonIgnoreProperties({ "rawId" })
    PublicKeyCredential<AuthenticatorAttestationResponse> credential;

}
