package demo.view;

import com.yubico.u2f.data.messages.AuthenticateRequestData;
import io.dropwizard.views.View;

import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticationView extends View {

    private final AuthenticateRequestData data;
    private final String username;

    public AuthenticateRequestData getData() {
        return data;
    }

    public String getDataJson() {
        return data.toJson();
    }

    public String getUsername() {
        return username;
    }

    public AuthenticationView(AuthenticateRequestData data, String username) {
        super("authenticate.ftl");
        this.data = checkNotNull(data);
        this.username = checkNotNull(username);
    }

}
