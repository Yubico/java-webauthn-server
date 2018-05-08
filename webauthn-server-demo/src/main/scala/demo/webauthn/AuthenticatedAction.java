package demo.webauthn;

import demo.webauthn.WebAuthnServer.SuccessfulAuthenticationResult;
import java.util.List;
import java.util.function.Function;
import scala.util.Either;

public interface AuthenticatedAction<T> extends Function<SuccessfulAuthenticationResult, Either<List<String>, T>> {
}
