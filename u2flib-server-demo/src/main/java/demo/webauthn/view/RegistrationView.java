package demo.webauthn.view;

import io.dropwizard.views.View;
import lombok.Getter;
import lombok.NonNull;

@Getter
public class RegistrationView extends View {

    private final String username;
    private final String requestId;
    private final String requestJson;

    public RegistrationView(@NonNull String username, @NonNull String requestId, @NonNull String requestJson) {
        super("register.ftl");
        this.username = username;
        this.requestId = requestId;
        this.requestJson = requestJson;
    }

}
