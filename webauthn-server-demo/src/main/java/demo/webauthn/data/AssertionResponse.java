package demo.webauthn.data;

import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Value;

@Value
public class AssertionResponse {

    ByteArray requestId;

    PublicKeyCredential<AuthenticatorAssertionResponse> credential;

}
