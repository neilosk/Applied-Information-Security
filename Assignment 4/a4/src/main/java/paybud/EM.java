package paybud;

/*
 * Interface to a mailing utility.
 */

import java.util.Properties;
import javax.mail.Session; 
import javax.mail.Message;
import javax.mail.Transport; 
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.InternetAddress;

public class EM{

    private static final String HOST = "smtp.gmail.com";          // SMTP server
    private static final String FROM = "paybudserver@gmail.com";  // in GMail, from-address & username happens to be the same
    private static final String PASS = "ptqpdkgfthyucasg";        // App-Specific Password

    public static boolean send(final String recipient, final String subject, final String text){
        final Properties props; final Session session; final Message msg;

        props = new Properties();
        props.setProperty("mail.smtp.ssl.enable", "true"); 
        props.setProperty("mail.smtp.host", HOST); // default port
        props.setProperty("mail.smtp.auth", "true");
        
        session = Session.getInstance(props);
        
        msg = new MimeMessage(session); // create a message to be sent via. SSL to the above SMTP server.
        try {
            msg.setFrom(new InternetAddress(FROM)); 
            msg.setRecipient(Message.RecipientType.TO, new InternetAddress(recipient)); 
            msg.setSubject(subject); 
            msg.setText(text);
            Transport.send(msg, FROM, PASS); 
            return true; // no error       
        } 
        catch (MessagingException mex) { // something went wrong somewhere ಠ_ಠ (SMTP, authentication)
            mex.printStackTrace();
            return false; // error
        } 
    } 
} 
