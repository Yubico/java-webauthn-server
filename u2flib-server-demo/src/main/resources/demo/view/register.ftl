<html>
<head>
<title>Java U2F Demo</title>

<script src="/assets/u2f-api.js"></script>

<script>
var request = ${data};
setTimeout(function() {
    u2f.register(request.registerRequests, request.authenticateRequests,
    function(data) {
        var form = document.getElementById('form');
        var reg = document.getElementById('tokenResponse');
        if(data.errorCode) {
            switch (data.errorCode) {
                case 4:
                    alert("This device is already registered.");
                    break;

                default:
                    alert("U2F failed with error: " + data.errorCode);
            }
        } else {
            reg.value=JSON.stringify(data);
            form.submit();
        }
    });
}, 1000);
</script>

</head>
    <body>
    <p>Touch your U2F token.</p>
        <form method="POST" action="finishRegistration" id="form" onsubmit="return false;">
            <input type="hidden" name="username" value="${username}"/>
            <input type="hidden" name="tokenResponse" id="tokenResponse"/>
        </form>
    </body>
</html>
