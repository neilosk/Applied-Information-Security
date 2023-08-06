
import {baseUrl, email, balance, balanceReq, logoutReq} from "/api.js";

$(document).ready( function() {

    console.log("Setting logout behavior on logout anchor.");
    $("#logout").click( function(){ logoutReq(); } );

    console.log("Setting email on page.");
    $("#email").html(email);

    balanceReq();
    
})

