package demo.webauthn;

import com.yubico.webauthn.data.MakePublicKeyCredentialOptions;
import lombok.EqualsAndHashCode;
import lombok.Value;

@Value
@EqualsAndHashCode(callSuper = false)
public class RegistrationRequest {

    String username;
    String requestId;
    MakePublicKeyCredentialOptions makePublicKeyCredentialOptions;

}
