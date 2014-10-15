package demo.view;

import io.dropwizard.views.View;

public class RegistrationView extends View {

  private final String data;

  public String getData() {
    return data;
  }

  public RegistrationView(String data) {
    super("register.ftl");
    this.data = data;

  }

}
