package demo.webauthn.view;

import demo.webauthn.CredentialRegistration;
import demo.webauthn.RegistrationResponse;
import io.dropwizard.views.View;
import lombok.Getter;

@Getter
public class FinishRegistrationView extends View {

    private final CredentialRegistration registration;
    private final String requestJson;
    private final RegistrationResponse response;
    private final String responseJson;

    public FinishRegistrationView(CredentialRegistration registration, String requestJson, RegistrationResponse response, String responseJson) {
        super("finishRegistration.ftl");

        this.registration = registration;
        this.requestJson = requestJson;
        this.response = response;
        this.responseJson = responseJson;
    }
}
