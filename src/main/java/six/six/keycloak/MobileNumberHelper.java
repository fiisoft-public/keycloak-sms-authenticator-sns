package six.six.keycloak;

import org.keycloak.models.UserModel;
import java.util.Arrays;


public class MobileNumberHelper {
    public static String getMobileNumber(UserModel user) {
        String mobileNumberCreds = user.getFirstAttribute(KeycloakSmsConstants.ATTR_MOBILE);

        String mobileNumber = null;

        if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
            mobileNumber = mobileNumberCreds;
        }

        return mobileNumber;
    }

    public static String generateMobileNumberHint(String mobileNumber) {
        // return a string which only display last 4 digits and the rest is "blurred" by star symbol
        char[] starSymbols = new char[mobileNumber.length() - 4];
        Arrays.fill(starSymbols, '*');
        String phoneAsLast4Digit = String.valueOf(starSymbols) + mobileNumber.substring(mobileNumber.length() - 4);
        return phoneAsLast4Digit;
    }
}
