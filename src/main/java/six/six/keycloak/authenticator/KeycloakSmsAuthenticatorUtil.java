package six.six.keycloak.authenticator;


import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;
import org.keycloak.theme.ThemeProvider;
import six.six.gateway.Gateways;
import six.six.gateway.SMSService;
import six.six.gateway.aws.snsclient.SnsNotificationService;
import six.six.gateway.govuk.notify.NotifySMSService;
import six.six.gateway.lyrasms.LyraSMSService;
import six.six.keycloak.EnvSubstitutor;
import six.six.keycloak.KeycloakSmsConstants;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * Created by joris on 18/11/2016.
 */
public class KeycloakSmsAuthenticatorUtil {

    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticatorUtil.class);
    public static AuthenticatorConfigModel CURRENT_APP_CONFIG = null;

    public static String getAttributeValue(UserModel user, String attributeName) {
        String result = null;
        List<String> values = user.getAttribute(attributeName);
        if (values != null && values.size() > 0) {
            result = values.get(0);
        }

        return result;
    }

    public static String getConfigString(AuthenticatorConfigModel config, String configName) {
        return getConfigString(config, configName, null);
    }

    public static String getConfigString(AuthenticatorConfigModel config, String configName, String defaultValue) {

        String value = defaultValue;

        if (config.getConfig() != null) {
            // Get value
            value = config.getConfig().get(configName);
        }

        return value;
    }

    public static Long getConfigLong(AuthenticatorConfigModel config, String configName) {
        return getConfigLong(config, configName, null);
    }

    public static Long getConfigLong(AuthenticatorConfigModel config, String configName, Long defaultValue) {

        Long value = defaultValue;

        if (config.getConfig() != null) {
            // Get value
            Object obj = config.getConfig().get(configName);
            try {
                value = Long.valueOf((String) obj); // s --> ms
            } catch (NumberFormatException nfe) {
                logger.error("Can not convert " + obj + " to a number.");
            }
        }

        return value;
    }

    public static Boolean getConfigBoolean(AuthenticatorConfigModel config, String configName) {
        return getConfigBoolean(config, configName, true);
    }

    public static Boolean getConfigBoolean(AuthenticatorConfigModel config, String configName, Boolean defaultValue) {

        Boolean value = defaultValue;

        if (config.getConfig() != null) {
            // Get value
            Object obj = config.getConfig().get(configName);
            try {
                value = Boolean.valueOf((String) obj); // s --> ms
            } catch (NumberFormatException nfe) {
                logger.error("Can not convert " + obj + " to a boolean.");
            }
        }

        return value;
    }

    public static String createMessage(String text,String code, String mobileNumber) {
        if (text == null) {
            return text;
        }

        return text
            .replaceAll("%sms-code%", code)
            .replaceAll("%phonenumber%", mobileNumber);
    }

    public static String setDefaultCountryCodeIfZero(String mobileNumber, String prefix, String condition) {
        if (prefix == null || mobileNumber.startsWith("+")) {
            return mobileNumber;
        }

        if (condition != null && mobileNumber.startsWith(condition)) {
            return prefix + mobileNumber.substring(1);
        }

        return prefix + mobileNumber;
    }

    /**
     * Check mobile number normative strcuture
     * @param mobileNumber
     * @return formatted mobile number
     */
    public static String checkMobileNumber(String mobileNumber) {

        PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
        try {
            Phonenumber.PhoneNumber phone = phoneUtil.parse(mobileNumber, null);
            mobileNumber = phoneUtil.format(phone,
                    PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            logger.error("Invalid phone number " + mobileNumber, e);
        }

        return mobileNumber;
    }


    public static String getMessage(AuthenticationFlowContext context, String key){
        String result=null;
        try {
            ThemeProvider themeProvider = context.getSession().getProvider(ThemeProvider.class, "extending");
            Theme currentTheme = themeProvider.getTheme(context.getRealm().getLoginTheme(), Theme.Type.LOGIN);
            Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
            result = currentTheme.getMessages(locale).getProperty(key);
        }catch (IOException e){
            logger.warn(key + "not found in messages");
        }
        return result;
    }

    public static String getMessage(RequiredActionContext context, String key){
        String result=null;
        try {
            ThemeProvider themeProvider = context.getSession().getProvider(ThemeProvider.class, "extending");
            Theme currentTheme = themeProvider.getTheme(context.getRealm().getLoginTheme(), Theme.Type.LOGIN);
            Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
            result = currentTheme.getMessages(locale).getProperty(key);
        }catch (IOException e){
            logger.warn(key + "not found in messages");
        }
        return result;
    }

    public static boolean sendSmsCode(String mobileNumber, String code, RequiredActionContext context) {
        /*
            Send SMS code in RequiredActionContext context
            This method is used in verify phone number step in the required action context
            This method required variable `config`
        */
        AuthenticatorConfigModel config = KeycloakSmsAuthenticatorUtil.CURRENT_APP_CONFIG;
        // Send an SMS
        KeycloakSmsAuthenticatorUtil.logger.debug("Sending " + code + "  to mobileNumber " + mobileNumber);

        String smsUsr = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_CLIENTTOKEN));
        String smsPwd = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_CLIENTSECRET));
        String gateway = getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY);

        // LyraSMS properties
        String endpoint = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY_ENDPOINT));
        boolean isProxy = getConfigBoolean(config, KeycloakSmsConstants.PROXY_ENABLED);

        // GOV.UK Notify properties
        String notifyApiKey = System.getenv(KeycloakSmsConstants.NOTIFY_API_KEY);
        String notifyTemplate = System.getenv(KeycloakSmsConstants.NOTIFY_TEMPLATE_ID);

        // Create the SMS message body
        String template = getMessage(context, KeycloakSmsConstants.CONF_PRP_SMS_TEXT);
        String smsText = createMessage(template, code, mobileNumber);

        boolean result;
        SMSService smsService;
        try {
            Gateways g = Gateways.valueOf(gateway);
            switch(g) {
                case LYRA_SMS:
                    smsService = new LyraSMSService(endpoint,isProxy);
                    break;
                case GOVUK_NOTIFY:
                    smsService = new NotifySMSService(notifyApiKey, notifyTemplate);
                    break;
                default:
                    smsService = new SnsNotificationService();
            }

            String addDefaultPrefix = setDefaultCountryCodeIfZero(mobileNumber, getMessage(context, KeycloakSmsConstants.MSG_MOBILE_PREFIX_DEFAULT), getMessage(context, KeycloakSmsConstants.MSG_MOBILE_PREFIX_CONDITION));
            String actualPhone = checkMobileNumber(addDefaultPrefix);
            result = smsService.send(actualPhone, smsText, smsUsr, smsPwd);
            return result;
       } catch(Exception e) {
            logger.error("Fail to send SMS " ,e );
            return false;
        }
    }

    public static boolean sendSmsCode(String mobileNumber, String code, AuthenticationFlowContext context) {
        /*
            Send SMS code in AuthenticationFlowContext context
        */
        final AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        // Send an SMS
        KeycloakSmsAuthenticatorUtil.logger.debug("Sending " + code + "  to mobileNumber " + mobileNumber);

        String smsUsr = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_CLIENTTOKEN));
        String smsPwd = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_CLIENTSECRET));
        String gateway = getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY);

        // LyraSMS properties
        String endpoint = EnvSubstitutor.envSubstitutor.replace(getConfigString(config, KeycloakSmsConstants.CONF_PRP_SMS_GATEWAY_ENDPOINT));
        boolean isProxy = getConfigBoolean(config, KeycloakSmsConstants.PROXY_ENABLED);

        // GOV.UK Notify properties
        String notifyApiKey = System.getenv(KeycloakSmsConstants.NOTIFY_API_KEY);
        String notifyTemplate = System.getenv(KeycloakSmsConstants.NOTIFY_TEMPLATE_ID);

        // Create the SMS message body
        String template = getMessage(context, KeycloakSmsConstants.CONF_PRP_SMS_TEXT);
        String smsText = createMessage(template, code, mobileNumber);

        boolean result;
        SMSService smsService;
        try {
            Gateways g = Gateways.valueOf(gateway);
            switch(g) {
                case LYRA_SMS:
                    smsService = new LyraSMSService(endpoint,isProxy);
                    break;
                case GOVUK_NOTIFY:
                    smsService = new NotifySMSService(notifyApiKey, notifyTemplate);
                    break;
                default:
                    smsService = new SnsNotificationService();
            }

            String addDefaultPrefix = setDefaultCountryCodeIfZero(mobileNumber, getMessage(context, KeycloakSmsConstants.MSG_MOBILE_PREFIX_DEFAULT), getMessage(context, KeycloakSmsConstants.MSG_MOBILE_PREFIX_CONDITION));
            String actualPhone = checkMobileNumber(addDefaultPrefix);

            result = smsService.send(actualPhone, smsText, smsUsr, smsPwd);
            return result;
       } catch(Exception e) {
            logger.error("Fail to send SMS " ,e );
            return false;
        }
    }

    public static String getSmsCode(long nrOfDigits) {
        if (nrOfDigits < 1) {
            throw new RuntimeException("Number of digits must be bigger than 0");
        }

        String format = "%0" + nrOfDigits + "d";
        double maxValue = Math.pow(10.0, nrOfDigits); // 10 ^ nrOfDigits;
        Random r = new Random();
        long code = (long) (r.nextFloat() * maxValue);

        return String.format(format, code);
    }

    /**
     * This validation matches the registration flow's validation
     * https://github.com/UKGovernmentBEIS/beis-mspsds/blob/master/keycloak/providers/registration-form/src/main/java/uk/gov/beis/mspsds/keycloak/providers/RegistrationMobileNumber.java#L55
     */
    public static boolean isPhoneNumberValid(String phoneNumber) {
        String formattedPhoneNumber = convertInternationalPrefix(phoneNumber);

        if (!isInternationalNumber(phoneNumber)) {
            String regexp = "\\+?\\d{1,15}";
            return formattedPhoneNumber.matches(regexp);
        }

        try {
            PhoneNumber parsedPhoneNumber = PhoneNumberUtil.getInstance().parse(formattedPhoneNumber, null);
            return PhoneNumberUtil.getInstance().isValidNumber(parsedPhoneNumber);
        } catch (NumberParseException e) {  
            return false;
        }
    }

    private static String convertInternationalPrefix(String phoneNumber) {
        String trimmedPhoneNumber = phoneNumber.trim();
        if (trimmedPhoneNumber.startsWith("00")) {
            return trimmedPhoneNumber.replaceFirst("00", "+");
        }
        return trimmedPhoneNumber;
    }

    private static boolean isInternationalNumber(String phoneNumber) {
        return phoneNumber.trim().startsWith("+");
    }
}
