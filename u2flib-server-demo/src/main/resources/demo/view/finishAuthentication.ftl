<html>
<head>
<title>Java U2F Demo</title>
</head>
<body>

    <#if success>
      <p>
        Successfully authenticated!
      </p>
    </#if>

    <#list messages as message>
      <p>${message}</p>
    </#list>

    <#include "navigation.ftl">

</body>
</html>
