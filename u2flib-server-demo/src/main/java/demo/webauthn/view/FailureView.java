package demo.webauthn.view;

import io.dropwizard.views.View;
import java.util.Arrays;
import java.util.List;
import lombok.Getter;

@Getter
public class FailureView extends View {

    private final List<String> messages;

    public FailureView(List<String> messages) {
        super("failure.ftl");

        this.messages = messages;
    }

    public FailureView(String... messages) {
        this(Arrays.asList(messages));
    }

    public FailureView(String message) {
        this(Arrays.asList(message));
    }

    public FailureView(Throwable cause) {
        this(cause.getMessage());
    }

}
