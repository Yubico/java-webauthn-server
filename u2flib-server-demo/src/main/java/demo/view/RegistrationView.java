package demo.view;

import io.dropwizard.views.View;

import static com.google.common.base.Preconditions.checkNotNull;

public class RegistrationView extends View {

    private final String username;
    private final String data;

    public String getUsername() {
        return username;
    }

    public String getData() {
        return data;
    }

    public RegistrationView(String data, String username) {
        super("register.ftl");
        this.data = checkNotNull(data);
        this.username = checkNotNull(username);
    }

}
