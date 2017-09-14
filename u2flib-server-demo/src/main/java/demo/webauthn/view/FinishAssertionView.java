package demo.webauthn.view;

import io.dropwizard.views.View;
import lombok.Getter;

@Getter
public class FinishAssertionView extends View {

    private final String requestJson;
    private final String responseJson;

    public FinishAssertionView(String requestJson, String responseJson) {
        super("finishAssertion.ftl");

        this.requestJson = requestJson;
        this.responseJson = responseJson;
    }
}
