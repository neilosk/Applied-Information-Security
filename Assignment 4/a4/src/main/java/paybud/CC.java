package paybud;

/*
 * Interface to a credit card payment system.
 */

public class CC {
    public static boolean deposit(String cardnumber, String amount){
        /*
         * Here we would connect to a remote service, and attempt to
         * deposit the given amount to the given credit card. If
         * successful, we would return true. Otherwise, we would
         * return false. Since this is out of scope of this
         * assignment, we are just going to return true here, always.
         */
        return true;
    }

    public static boolean withdraw(String cardnumber, String amount){
        /*
         * Here we would connect to a remote service, and attempt to
         * withdraw the given amount from the given credit card. If
         * successful, we would return true. Otherwise, we would
         * return false. Since this is out of scope of this
         * assignment, we are just going to return true here, always.
         */
        return true;
    }
}
