package demo.webauthn;

import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Value;

@Value
public class RegistrationResponse {

    String requestId;
    PublicKeyCredential<AuthenticatorAttestationResponse> credential;

}
