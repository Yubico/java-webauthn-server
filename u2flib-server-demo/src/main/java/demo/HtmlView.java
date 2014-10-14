package demo;

import io.dropwizard.views.View;

public class HtmlView extends View {

  private final String data;
  private final String method;

  public String getData() {
    return data;
  }
  public String getMethod() {
    return method;
  }

  public HtmlView(String method, String data) {
    super("html.ftl");
    this.data = data;
    this.method = method;
  }

}
