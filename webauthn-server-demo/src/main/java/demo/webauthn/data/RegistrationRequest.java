package demo.webauthn.data;

import com.yubico.util.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import java.util.Optional;
import lombok.EqualsAndHashCode;
import lombok.Value;

@Value
@EqualsAndHashCode(callSuper = false)
public class RegistrationRequest {

    String username;
    Optional<String> credentialNickname;
    ByteArray requestId;
    PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;

}
