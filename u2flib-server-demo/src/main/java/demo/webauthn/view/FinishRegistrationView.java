package demo.webauthn.view;

import demo.webauthn.CredentialRegistration;
import demo.webauthn.RegistrationRequest;
import demo.webauthn.RegistrationResponse;
import io.dropwizard.views.View;
import lombok.Getter;

@Getter
public class FinishRegistrationView extends View {

    private final CredentialRegistration registration;
    private final String requestJson;
    private final RegistrationResponse response;

    public FinishRegistrationView(CredentialRegistration registration, String requestJson, RegistrationResponse response) {
        super("finishRegistration.ftl");

        this.registration = registration;
        this.requestJson = requestJson;
        this.response = response;
    }
}
