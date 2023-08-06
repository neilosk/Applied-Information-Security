
import {baseUrl, email, balance, logoutReq, balanceReq, withdrawReq} from "/api.js";

$(document).ready(function() {

    console.log("Setting email on page.");
    $("#email").html(email);

    console.log("Setting logout behavior on logout anchor.");
    $("#logout").click( function () { logoutReq(); });

    console.log("Setting withdraw behavior on withdraw button.");
    $("#withdraw").click( function () { withdrawReq(); });

    balanceReq();
    
});
