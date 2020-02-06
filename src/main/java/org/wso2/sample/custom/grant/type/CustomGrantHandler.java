package org.wso2.sample.custom.grant.type;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationCodeGrantHandler;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import javax.xml.namespace.QName;
import java.util.Iterator;
import java.util.Properties;

public class CustomGrantHandler extends AuthorizationCodeGrantHandler {

    public static final String CLAIM_URI = "claimURI";
    public static final String CLIENT_PARAMETER = "clientParameter";
    public static final String SINGLE_DEVICE_CONFIG = "SingleDeviceConfigs";
    public static final String CONFIG_ELEM_OAUTH = "OAuth";
    public static String CLIENT_UUID_PARAM = "uuidClient";
    public static String USER_CLAIM;
    private static final String AUTHORIZATION_CODE_PARAM = "code";
    private static Properties properties = new Properties();
    private static Log log = LogFactory.getLog(CustomGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        String uuidClient = null;  //UUID sent by Client
        String uuidIS; //UUID in IS side
        for (RequestParameter parameter : tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters()) {
            if (AUTHORIZATION_CODE_PARAM.equals(parameter.getKey())) {
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAuthorizationCode(parameter.getValue()[0]);

            } else if (CLIENT_UUID_PARAM.equals(parameter.getKey())) {
                uuidClient = parameter.getValue()[0];
            }
        }
//        tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAuthorizationCode(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters()[0].getValue()[0].toString());
        tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        super.validateGrant(tokReqMsgCtx);

        if (CLIENT_UUID_PARAM == null || USER_CLAIM == null) {
            readPropertiesFromFile();
        }

        try {
            uuidIS = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                    .getUserClaimValue(tokReqMsgCtx.getAuthorizedUser().getUserName(), USER_CLAIM, null);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("User Store Exception", e);
            }
            throw new IdentityOAuth2Exception("Invalid User Cannot find user store claim");
        }

        if (uuidClient != null) {//Checking if UUID sent by the user is null
            if (uuidIS != null) {
                if (uuidIS.equals(uuidClient)) {
                    return true;   //valid user from same device
                } else {
                    throw new IdentityOAuth2Exception("Invalid Login.Cannot login with multiple devices. Please contact Bank");//new device invalid user
                }
            } else {
                //Invalid Request
                throw new IdentityOAuth2Exception("Invalid Login. Please contact the Bank");
            }
        } else {
            //Invalid Request
            throw new IdentityOAuth2Exception("Invalid Login. Please contact the Bank");
        }

    }

    private void readPropertiesFromFile() {
        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthElem = configParser.getConfigElement(CONFIG_ELEM_OAUTH);

        if (oauthElem == null) {
            log.error("OAuth element is not available.");
            return;
        }
        parseSingleDeviceConfig(oauthElem);
    }

    private void parseSingleDeviceConfig(OMElement singleDeviceConfig) {
        if (singleDeviceConfig == null) {
            return;
        }

        Iterator validators = singleDeviceConfig.getChildrenWithLocalName(SINGLE_DEVICE_CONFIG);
        if (validators != null) {
            for (; validators.hasNext(); ) {
                OMElement validator = (OMElement) validators.next();
                if (validator != null) {
                    CLIENT_UUID_PARAM = validator.getAttributeValue(new QName(CLIENT_PARAMETER));
                    USER_CLAIM = validator.getAttributeValue(new QName(CLAIM_URI));
                }
            }
        }
    }
}
