package demo.webauthn;

import com.yubico.util.Either;
import demo.webauthn.WebAuthnServer.SuccessfulAuthenticationResult;
import java.util.List;
import java.util.function.Function;

public interface AuthenticatedAction<T> extends Function<SuccessfulAuthenticationResult, Either<List<String>, T>> {
}
