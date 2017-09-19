package demo.webauthn.view;

import com.yubico.webauthn.data.Credential;
import demo.webauthn.CredentialRegistration;
import io.dropwizard.views.View;
import java.util.Collection;
import lombok.Getter;

@Getter
public class FinishAssertionView extends View {

    private final String requestJson;
    private final String responseJson;
    private final String registrationsJson;
    private final Collection<CredentialRegistration> registrations;

    public FinishAssertionView(String requestJson, String responseJson, String registrationsJson, Collection<CredentialRegistration> registrations) {
        super("finishAssertion.ftl");

        this.requestJson = requestJson;
        this.responseJson = responseJson;
        this.registrationsJson = registrationsJson;
        this.registrations = registrations;
    }
}
