
import {baseUrl, email, balance, logoutReq, balanceReq, sendReq} from "/api.js";

$(document).ready(function() {

    console.log("Setting email on page.");
    $("#email").html(email);

    console.log("Setting logout behavior on logout anchor.");
    $("#logout").click( function () { logoutReq(); });

    console.log("Setting send behavior on send button.");
    $("#send").click( function () { sendReq(); });

    balanceReq();
    
});
