package demo.webauthn.view;

import io.dropwizard.views.View;
import lombok.Getter;

@Getter
public class AssertionView extends View {

    private final String username;
    private final String requestId;
    private final String requestJson;

    public AssertionView(String username, String requestId, String requestJson) {
        super("assert.ftl");

        this.username = username;
        this.requestId = requestId;
        this.requestJson = requestJson;
    }

}
