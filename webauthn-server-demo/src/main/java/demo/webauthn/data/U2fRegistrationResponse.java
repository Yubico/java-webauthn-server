package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import lombok.NonNull;
import lombok.Value;

@Value
public class U2fRegistrationResponse {

    private final ByteArray requestId;
    private final U2fCredential credential;

    @JsonCreator
    public U2fRegistrationResponse(
        @NonNull @JsonProperty("requestId") ByteArray requestId,
        @NonNull @JsonProperty("credential") U2fCredential credential
    ) {
        this.requestId = requestId;
        this.credential = credential;
    }

}
