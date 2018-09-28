package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.NonNull;
import lombok.Value;

@Value
public class U2fCredential {

    private final U2fCredentialResponse u2fResponse;

    @JsonCreator
    public U2fCredential(
        @NonNull @JsonProperty("u2fResponse") U2fCredentialResponse u2fResponse
    ) {
        this.u2fResponse = u2fResponse;
    }

}
