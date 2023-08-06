
import { baseUrl, createReq, forgotReq, loginReq } from "/api.js";

function emailForm () {
    $("#email").   css("display", "inline");
    $("#password").css("display", "none");
    $("#continue").css("display", "inline");
    $("#forgot").  css("display", "inline");
    $("#login").   css("display", "none");
    $("#create").  css("display", "none");
    $("#back").    css("display", "none");
}

function passwordForm () {
    $("#email").   css("display", "none");
    $("#password").css("display", "inline");
    $("#continue").css("display", "none");
    $("#forgot").  css("display", "none");
    $("#login").   css("display", "inline");
    $("#create").  css("display", "inline");
    $("#back").    css("display", "inline");
}

$(document).ready(function() {

    console.log("Setting continue behavior on continue button.");
    $("#continue").click( function(){ passwordForm(); } );

    console.log("Setting forgot behavior on forgot button.");
    $("#forgot").click( function(){ forgotReq(); } );
    
    console.log("Setting login behavior on login button.");
    $("#login").click( function(){ loginReq(); } );

    console.log("Setting create behavior on create button.");
    $("#create").click( function(){ createReq(); } );

    console.log("Setting back behavior on back button.");
    $("#back").click( function(){ emailForm(); } );

    console.log("Setting RETURN keypress behavior.");
    $("#email").keypress(function(event) { 
        if (event.keyCode === 13) { /* pressing RETURN */
            $("#continue").click(); 
        } 
    }); 
    $("#password").keypress(function(event) { 
        if (event.keyCode === 13) { /* pressing RETURN */
            $("#login").click(); 
        } 
    });

    emailForm();
});
