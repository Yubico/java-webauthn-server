package demo.webauthn;

import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Value;

@Value
public class AssertionResponse {

    String requestId;
    PublicKeyCredential<AuthenticatorAssertionResponse> credential;

}
