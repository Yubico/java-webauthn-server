package demo.webauthn.view;

import io.dropwizard.views.View;
import java.util.Arrays;
import java.util.List;
import lombok.Getter;

@Getter
public class RegistrationFailedView extends View {

    private final List<String> messages;

    public RegistrationFailedView(List<String> messages) {
        super("registrationFailed.ftl");

        this.messages = messages;
    }

    public RegistrationFailedView(String message) {
        this(Arrays.asList(message));
    }

    public RegistrationFailedView(Throwable cause) {
        this(cause.getMessage());
    }

}
