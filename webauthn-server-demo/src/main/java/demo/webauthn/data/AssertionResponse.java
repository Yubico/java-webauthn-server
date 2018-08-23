package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.util.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Value;

@Value
public class AssertionResponse {

    private final ByteArray requestId;

    private final PublicKeyCredential<AuthenticatorAssertionResponse> credential;

    public AssertionResponse(
        @JsonProperty("requestId") ByteArray requestId,
        @JsonProperty("credential") PublicKeyCredential<AuthenticatorAssertionResponse> credential
    ) {
        this.requestId = requestId;
        this.credential = credential;
    }

}
