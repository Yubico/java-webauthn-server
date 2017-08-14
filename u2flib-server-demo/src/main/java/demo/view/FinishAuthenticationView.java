package demo.view;

import io.dropwizard.views.View;
import java.util.Collections;
import java.util.List;
import lombok.Getter;

@Getter
public class FinishAuthenticationView extends View {

    private final boolean success;
    private final List<String> messages;

    public FinishAuthenticationView(boolean success, List<String> messages) {
        super("finishAuthentication.ftl");
        this.success = success;
        this.messages = messages;
    }

    public FinishAuthenticationView(boolean success, String message) {
        this(success, Collections.singletonList(message));
    }

    public FinishAuthenticationView(boolean success) {
        this(success, Collections.<String>emptyList());
    }

}
