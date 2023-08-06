package paybud;

/*
 * Interface to the PayBud database.
 */

import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Optional;


import org.passay.*;



public class DB {

    private static final String URL = "jdbc:sqlite:db/paybud.db"; // database we are connecting to.

  
    //     public boolean isPasswordValid(String password) {
    //     // Define your password policy here.
    //     PasswordValidator validator = new PasswordValidator(Arrays.asList(
    //    // At least 8 characters length
    //    new LengthRule(8, 128),

    //    // At least one upper-case character
    //    new CharacterRule(EnglishCharacterData.UpperCase, 1),

    //    // At least one lower-case character
    //    new CharacterRule(EnglishCharacterData.LowerCase, 1),

    //    // At least one digit character
    //    new CharacterRule(EnglishCharacterData.Digit, 1),

    //    // At least one symbol (special character)
    //    new CharacterRule(EnglishCharacterData.Special, 1),

    //    // No whitespace
    //    new WhitespaceRule()
    //     ));

    //     RuleResult result = validator.validate(new PasswordData(password));
    //     }
    

    
    
    public static boolean create(final String email, final String password) {
     
        // Define your password policy here.
        PasswordValidator validator = new PasswordValidator(Arrays.asList(
       // At least 8 characters length
       new LengthRule(8, 128),
       // At least one upper-case character
       new CharacterRule(EnglishCharacterData.UpperCase, 1),
       // At least one lower-case character
       new CharacterRule(EnglishCharacterData.LowerCase, 1),
       // At least one digit character
       new CharacterRule(EnglishCharacterData.Digit, 1),
       // At least one symbol (special character)
       new CharacterRule(EnglishCharacterData.Special, 1),
       // No whitespace
       new WhitespaceRule()
        ));

        RuleResult result = validator.validate(new PasswordData(password));

    if (result.isValid()) {
        final String iu = "INSERT INTO users VALUES ('" + email + "', '" + password + "');";
        final String ia = "INSERT INTO accounts VALUES ('" + email + "', '0'); ";
        try {
            Connection c; Statement s;
            c = DriverManager.getConnection(URL);
            c.setAutoCommit(false); // enter transaction mode
            s = c.createStatement();
            s.executeUpdate(iu);
            s = c.createStatement();
            s.executeUpdate(ia);
            c.commit();             // commit transaction
            c.setAutoCommit(true);  // exit transaction mode
            c.close();
            return true;
        } catch ( Exception e ) {}
        return false; // exception occurred; malformed SQL query?
    } else {
        // If password does not meet the policy, handle it here.
        // You can fetch the failed rules and return appropriate messages.
        return false;
    }
}






        
   

    public static Optional<String> login( final String email, final String password ) {
    final String q = "SELECT * FROM users WHERE email=? AND password=?";
    try {
        Connection c = DriverManager.getConnection(URL);
        PreparedStatement ps = c.prepareStatement(q);
        ps.setString(1, email);
        ps.setString(2, password);
        ResultSet r = ps.executeQuery();
        String u;
        if ( r.next() ){ // true iff result set non-empty, implying email-password combination found.
            u = r.getString("email");
        } else {
            u = null;
        }
        c.close();
        return Optional.ofNullable(u); // empty iff u = null
    } catch ( Exception e ) {
        e.printStackTrace(); // It is generally a good idea to print or log the exception
    }
    return null; // exception occurred; malformed SQL query?
}
    
    public static Optional<String> user( final String email ) {
        final String q = "SELECT * FROM users WHERE email='" + email + "'";
        try {
            Connection c; Statement s; ResultSet r; String u;
            c = DriverManager.getConnection(URL);
            s = c.createStatement();
            r = s.executeQuery(q);
            if ( r.next() ){ // true iff result set non-empty, implying email found.
                u = r.getString("email");
            } else {
                u = null;
            }
            c.close();
            return Optional.ofNullable(u); // empty iff u = null
        } catch ( Exception e ) {}
        return null; // exception occurred; malformed SQL query?
    }
    
    public static Optional<String> password( final String email ) {
        final String q = "SELECT * FROM users WHERE email='" + email + "'";
        try {
            Connection c; Statement s; ResultSet r; String u;
            c = DriverManager.getConnection(URL);
            s = c.createStatement();
            r = s.executeQuery(q);
            if ( r.next() ){ // true iff result set non-empty, implying email found.
                u = r.getString("password");
            } else {
                u = null;
            }
            c.close();
            return Optional.ofNullable(u); // empty iff u = null
        } catch ( Exception e ) {}
        return null; // exception occurred; malformed SQL query?
    }
    
    public static Optional<String> balance( final String email ) {
        final String q = "SELECT balance FROM accounts WHERE email='" + email + "'";
        try {
            Connection c; Statement s; ResultSet r; String b;
            c = DriverManager.getConnection(URL);
            s = c.createStatement();
            r = s.executeQuery(q);
            if ( r.next() ){ // true iff user has an account
                b = r.getString("balance"); // null iff no rows returned
            } else {
                b = null;
            }
            c.close();
            return Optional.ofNullable(b);
        } catch ( Exception e ) {}
        return null; // exception occurred; malformed SQL query?
    }
    
    public static boolean send( final String email, final String to, final String amount ) {
        final String uf = "UPDATE accounts SET balance = balance - " + amount + " WHERE email = '" + email + "';";
        final String ut = "UPDATE accounts SET balance = balance + " + amount + " WHERE email = '" + to + "';";
        try {
            Connection c; Statement s;
            c = DriverManager.getConnection(URL);
            c.setAutoCommit(false);
            s = c.createStatement();
            s.executeUpdate(uf);
            s = c.createStatement();
            s.executeUpdate(ut);
            c.commit();
            c.setAutoCommit(true);
            c.close();
            return true;
        } catch ( Exception e ) {}
        return false; // exception occurred; malformed SQL query?
    }
    
    public static boolean deposit( final String email, final String amount ) {
        final String u = "UPDATE accounts SET balance = balance + " + amount + " WHERE email = '" + email + "';";
        try {
            Connection c; Statement s;
            c = DriverManager.getConnection(URL);
            s = c.createStatement();
            s.executeUpdate(u);
            c.close();
            return true;
        } catch ( Exception e ) {}
        return false; // exception occurred; malformed SQL query?
    }
    
    public static boolean withdraw( final String email, final String amount ) {
        final String u = "UPDATE accounts SET balance = balance - " + amount + " WHERE email = '" + email + "';";
        try {
            Connection c; Statement s;
            c = DriverManager.getConnection(URL);
            s = c.createStatement();
            s.executeUpdate(u);
            c.close();
            return true;
        } catch ( Exception e ) {}
        return false; // exception occurred; malformed SQL query?
    }
}
