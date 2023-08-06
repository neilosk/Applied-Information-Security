
import {baseUrl, email, balance, logoutReq, balanceReq, depositReq} from "/api.js";

$(document).ready(function() {

    console.log("Setting email on page.");
    $("#email").html(email);

    console.log("Setting logout behavior on logout anchor.");
    $("#logout").click( function () { logoutReq(); });

    console.log("Setting deposit behavior on deposit button.");
    $("#deposit").click( function () { depositReq(); });

    balanceReq();
    
});
