package demo.webauthn.data;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import lombok.EqualsAndHashCode;
import lombok.Value;

@Value
@EqualsAndHashCode(callSuper = false)
public class RegistrationRequest {

    String username;
    String credentialNickname;
    ByteArray requestId;
    PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;

}
