package demo.view;

import io.dropwizard.views.View;

public class AuthenticationView extends View {

    private final String data;
    private final String username;

    public String getData() {
        return data;
    }

    public String getUsername() {
        return username;
    }

    public AuthenticationView(String data, String username) {
        super("authenticate.ftl");
        this.data = data;
        this.username = username;

    }

}
