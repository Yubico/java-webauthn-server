package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Value;

@Value
public class AssertionResponse {

    String requestId;

    @JsonIgnoreProperties({ "rawId" })
    PublicKeyCredential<AuthenticatorAssertionResponse> credential;

}
