package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import lombok.NonNull;
import lombok.Value;

@Value
public class U2fCredentialResponse {

    private final ByteArray keyHandle;
    private final ByteArray publicKey;
    private final ByteArray attestationCert;

    @JsonCreator
    public U2fCredentialResponse(
        @NonNull @JsonProperty("keyHandle") ByteArray keyHandle,
        @NonNull@JsonProperty("publicKey") ByteArray publicKey,
        @NonNull@JsonProperty("attestationCert") ByteArray attestationCert
    ) {
        this.keyHandle = keyHandle;
        this.publicKey = publicKey;
        this.attestationCert = attestationCert;
    }

}
