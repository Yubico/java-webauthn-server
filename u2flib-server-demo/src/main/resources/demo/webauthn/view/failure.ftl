<html>
<head>
<meta charset="utf-8"/>
<title>Java WebAuthn Demo</title>
</head>
<body>

    <#list messages>
      <#items as item>
        <p>${item}</p>
      </#items>
    </#list>

    <#include "/demo/view/navigation.ftl">

</body>
</html>
