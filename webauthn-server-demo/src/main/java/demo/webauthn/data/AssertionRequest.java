package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;

@Value
public class AssertionRequest {

    @NonNull
    private final ByteArray requestId;

    @NonNull
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @NonNull
    private final Optional<String> username;

    @NonNull
    @JsonIgnore
    private final transient com.yubico.webauthn.data.AssertionRequest request;

    public AssertionRequest(
        @NonNull
        ByteArray requestId,
        @NonNull
        com.yubico.webauthn.data.AssertionRequest request
    ) {
        this.requestId = requestId;
        this.publicKeyCredentialRequestOptions = request.getPublicKeyCredentialRequestOptions();
        this.username = request.getUsername();
        this.request = request;

    }

}
