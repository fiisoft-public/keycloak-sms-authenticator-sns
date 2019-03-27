package six.six.keycloak.requiredaction.action.required;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import six.six.keycloak.KeycloakSmsConstants;
import six.six.keycloak.MobileNumberHelper;
import six.six.keycloak.authenticator.KeycloakSmsAuthenticator;
import six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Date;

import static six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil.isPhoneNumberValid;

/**
 * Created by nickpack on 15/08/2017.
 */
public class KeycloakSmsMobilenumberRequiredAction implements RequiredActionProvider {
    private static Logger logger = Logger.getLogger(KeycloakSmsMobilenumberRequiredAction.class);
    public static final String PROVIDER_ID = "sms_auth_check_mobile";

    public void evaluateTriggers(RequiredActionContext context) {
        logger.debug("evaluateTriggers called ...");
    }



    public void requiredActionChallenge(RequiredActionContext context) {
        logger.debug("requiredActionChallenge called ...");

        UserModel user = context.getUser();
        String mobileNumber = MobileNumberHelper.getMobileNumber(user);

        Response challenge = context.form()
                .setAttribute("phoneNumber", mobileNumber)
                .createForm("sms-validation-mobile-number.ftl");
        context.challenge(challenge);
    }

    public void processAction(RequiredActionContext context) {
        logger.debug("processAction called ...");

        String answer = (context.getHttpRequest().getDecodedFormParameters().getFirst("mobile_number"));
        if (answer != null && answer.length() > 0 && isPhoneNumberValid(answer)) {
            logger.debug("Valid matching mobile numbers supplied, save credential ...");
            List<String> mobileNumber = new ArrayList<>();
            mobileNumber.add(answer);

            UserModel user = context.getUser();
            user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber);

            logger.debug("It's time to verify this phone number");

            boolean result = this.send2FACodeViaSMS(context, MobileNumberHelper.getMobileNumber(user));
            logger.debug("SMS send status: " + result);

            if (result) {
                Response challenge = context.form().createForm("sms-verify-phone-validation.ftl");
                context.challenge(challenge);

                List<String> mobileNumberCreds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE);
                if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
                    user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED,mobileNumberCreds);
                }

            } else {
                Response challenge = context.form()
                    .setError("sms-auth.not.send")
                    .createForm("sms-validation-error.ftl");
                context.challenge(challenge);
            }

        } else {
            logger.debug("The field wasn\'t complete or is an invalid number...");
            Response challenge = context.form()
                    .setError("mobile_number.no.valid")
                    .createForm("sms-validation-mobile-number.ftl");
            context.challenge(challenge);
        }
    }

    private boolean send2FACodeViaSMS(RequiredActionContext context, String mobileNumber) {
        logger.debug("send Code to verify phone: " + mobileNumber);

        AuthenticatorConfigModel config = KeycloakSmsAuthenticatorUtil.CURRENT_APP_CONFIG;

        long nrOfDigits = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
        logger.debug("Using nrOfDigits " + nrOfDigits);

        long ttl = KeycloakSmsAuthenticatorUtil.getConfigLong(config, KeycloakSmsConstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s

        logger.debug("Using ttl " + ttl + " (s)");

        String code = KeycloakSmsAuthenticatorUtil.getSmsCode(nrOfDigits);

        this.storeSMSCode(context, code, new Date().getTime() + (ttl * 1000)); // s --> ms
        logger.debug("Sending code to mobile number: " + mobileNumber + ", code is: " + code);
        return KeycloakSmsAuthenticatorUtil.sendSmsCode(mobileNumber, code, context);
    }

    // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private void storeSMSCode(RequiredActionContext context, String code, Long expiringAt) {
        UserCredentialModel credentials = new UserCredentialModel();
        credentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);
        credentials.setValue(code);

        context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(), credentials);

        credentials.setType(KeycloakSmsConstants.USR_CRED_MDL_SMS_EXP_TIME);
        credentials.setValue((expiringAt).toString());
        context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(), credentials);
    }

    public void close() {
        logger.debug("close called ...");
    }
}
