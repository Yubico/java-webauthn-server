package demo.webauthn;

import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import java.util.Optional;
import lombok.Value;

@Value
public class AssertionRequest {

    Optional<String> username;
    String requestId;
    PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

}
