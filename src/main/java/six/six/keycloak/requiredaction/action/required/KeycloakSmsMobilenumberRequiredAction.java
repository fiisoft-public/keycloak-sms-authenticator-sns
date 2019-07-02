package six.six.keycloak.requiredaction.action.required;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import six.six.keycloak.KeycloakSmsConstants;
import six.six.keycloak.MobileNumberHelper;
import six.six.keycloak.authenticator.KeycloakSmsAuthenticator;
import six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Date;

import javax.ws.rs.core.MultivaluedMap;
import static six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil.isPhoneNumberValid;

/**
 * Created by nickpack on 15/08/2017.
 */
public class KeycloakSmsMobilenumberRequiredAction implements RequiredActionProvider {
    private static Logger logger = Logger.getLogger(KeycloakSmsMobilenumberRequiredAction.class);
    public static final String PROVIDER_ID = "sms_auth_check_mobile";

    private enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }

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

        String phoneNumberInput = context.getHttpRequest().getDecodedFormParameters().getFirst(KeycloakSmsConstants.ATTR_MOBILE);
        UserModel user = context.getUser();
        String smsCode = context.getHttpRequest().getDecodedFormParameters().getFirst(KeycloakSmsConstants.ANSW_SMS_CODE);
        logger.debug("RequiredActionChain recieve phone: " + phoneNumberInput + " and smsCode: " + smsCode);


        if (phoneNumberInput != null && phoneNumberInput.length() > 0 && isPhoneNumberValid(phoneNumberInput)) {
            logger.debug("Valid matching mobile numbers supplied, save credential ...");
            List<String> mobileNumber = new ArrayList<>();
            mobileNumber.add(phoneNumberInput);


            user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE, mobileNumber);

            logger.debug("It's time to verify this phone number");

            String activeMobileNumber = MobileNumberHelper.getMobileNumber(user);
            boolean result = this.send2FACodeViaSMS(context, activeMobileNumber);

            logger.debug("SMS send status: " + result);
            String mobileNumberHint = MobileNumberHelper.generateMobileNumberHint(activeMobileNumber);

            if (result) {
                Response challenge = context.form()
                    .setAttribute("mobileNumberHint", mobileNumberHint)
                    .createForm("sms-verify-phone-validation.ftl");
                context.challenge(challenge);

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

        if (smsCode != null) {
            logger.debug("Check the smsCode to verify phone");
            CODE_STATUS status = this.validateCode(context, smsCode);

            String activeMobileNumber = MobileNumberHelper.getMobileNumber(user);
            String mobileNumberHint = MobileNumberHelper.generateMobileNumberHint(activeMobileNumber);

            switch (status) {
                case VALID:
                    context.success();

                    List<String> mobileNumberCreds = user.getAttribute(KeycloakSmsConstants.ATTR_MOBILE);
                    if (mobileNumberCreds != null && !mobileNumberCreds.isEmpty()) {
                        user.setAttribute(KeycloakSmsConstants.ATTR_MOBILE_VERIFIED, mobileNumberCreds);
                    }
                    logger.debug("verified number: Success");
                    break;

                case INVALID:
                    logger.debug("verified number: Invalid code");
                    Response challenge = context.form()
                            .setAttribute("mobileNumberHint", mobileNumberHint)
                            .setError("sms-auth.code.invalid")
                            .createForm("sms-verify-phone-validation.ftl");
                    context.challenge(challenge);
                    break;

                case EXPIRED:
                    logger.debug("verified number: Expired");
                    challenge = context.form()
                        .setAttribute("mobileNumberHint", mobileNumberHint)
                        .setError("sms-auth.code.expired")
                        .createForm("sms-verify-phone-validation.ftl");
                    context.challenge(challenge);
                    break;
            }
        } else {
            logger.debug("RequiredActionChain: post action failed");
        }
    }

    protected CODE_STATUS validateCode(RequiredActionContext context, String enteredCode) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.debug("validateCode called ... ");

        KeycloakSession session = context.getSession();

        List codeCreds = session.userCredentialManager().getStoredCredentialsByType(context.getRealm(), context.getUser(), KeycloakSmsConstants.USR_CRED_MDL_SMS_CODE);

        CredentialModel expectedCode = (CredentialModel) codeCreds.get(0);

        logger.debug("Expected code = " + expectedCode + "    entered code = " + enteredCode);

        if (expectedCode != null) {
            result = enteredCode.equals(expectedCode.getValue()) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
        }
        logger.debug("result : " + result);
        return result;
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
