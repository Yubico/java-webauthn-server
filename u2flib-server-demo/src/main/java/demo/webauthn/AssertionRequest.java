package demo.webauthn;

import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import lombok.Value;

@Value
public class AssertionRequest {

    String username;
    String requestId;
    PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

}
