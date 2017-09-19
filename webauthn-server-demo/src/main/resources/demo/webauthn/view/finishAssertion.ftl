<html>
<head>
<meta charset="utf-8"/>
<title>Java WebAuthn Demo</title>

<script>

window.onload = function() {
  const preElements = document.getElementsByTagName("pre");
  for (var i = 0; i < preElements.length; ++i) {
    preElements[i].innerHTML = JSON.stringify(JSON.parse(preElements[i].innerHTML), false, 2);
  }
}
</script>

</head>
<body>

    <p>Successfully authenticated!</p>

    <h3> Your registered credentials: </h3>

    <#list registrations>
      <table>

        <thead>
          <tr>
            <th> Nickname </th>
            <th> Registered </th>
            <th> Actions </th>
            <th> Details </th>
          </tr>
        </thead>

        <tbody>
          <#items as registration>
            <tr>
              <td> ${registration.getCredentialNickname()} </td>
              <td> ${registration.getRegistrationTime()} </td>
              <td>

                <form action="deregister" method="post">
                  <input type="hidden" name="username" value="${registration.getUsername()}"/>
                  <input type="hidden" name="credentialId" value="${registration.getRegistration().keyId().idBase64()}"/>
                  <button type="submit"> Deregister </button>
                </form>

              </td>

              <td>
                <pre>${registration.toJson()}</pre>
              </td>
            </tr>
          </#items>
        </tbody>
      </table>
    </#list>


    <h3> Request </h3>
    <pre id="request">${requestJson}</pre>

    <h3> Response </h3>
    <p>Properties prefixed with <code>_</code> are parsed versions of the corresponding Base64 encoded binary blob.
    Properties prefixed with <code>@</code> are implementation-specific deserialization hints.</p>
    <pre id="response">${responseJson}</pre>

    <#include "/demo/view/navigation.ftl">

</body>
</html>
