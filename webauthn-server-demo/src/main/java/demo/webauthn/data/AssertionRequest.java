package demo.webauthn.data;

import com.yubico.webauthn.data.ByteArray;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Value;

@Value
@Builder
public class AssertionRequest {

    private final ByteArray requestId;
    private final com.yubico.webauthn.data.AssertionRequest request;

}
