package org.wso2.sample.custom.grant.type;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationCodeGrantHandler;
import org.wso2.carbon.identity.mgt.constants.IdentityMgtConstants;

import java.io.*;
import java.util.Properties;

public class CustomGrantHandler extends AuthorizationCodeGrantHandler {

    public static final String CLIENT_UUID_PARAM = "uuidClient";
    public static Properties properties = new Properties();
    private static Log log = LogFactory.getLog(CustomGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);
        if (properties.isEmpty()) {
            readPropertiesFromFile();
        }
        String singleDeviceClaim = (properties.getProperty("Single.Device.Claim").trim());
        if (singleDeviceClaim.isEmpty()) {
            log.info("Single Device Claim Value is not configured. Skipping the validation");
            return true;
        }
        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String uuidClient = null;  //UUID sent by Client
        String uuidIS = null; //UUID in IS side
        // find out Uuid Parameter
        for (RequestParameter parameter : parameters) {
            if (CLIENT_UUID_PARAM.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    uuidClient = parameter.getValue()[0];
                }
            }
        }

        try {
            uuidIS = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                    .getUserClaimValue(tokReqMsgCtx.getAuthorizedUser().getUserName(), singleDeviceClaim, null);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("User Store Exception", e);
            }
            throw new IdentityOAuth2Exception("Invalid User");
        }

        if (uuidClient != null) {//Checking if UUID sent by the user is null
            if (uuidIS != null) {
                if (uuidIS.equals(uuidClient)) {
                    return true;   //valid user from same device
                } else {
                    throw new IdentityOAuth2Exception("Invalid Login.Cannot login with multiple devices.Please contact Bank");//new device invalid user
                }
            } else {
                //Invalid Request
                throw new IdentityOAuth2Exception("Invalid Login.Cannot login with multiple devices.Please contact Bank");
            }
        } else {
            //Invalid Request
            throw new IdentityOAuth2Exception("Invalid Login.Cannot login with multiple devices.Please contact Bank");
        }
    }

    private static void readPropertiesFromFile() {
        InputStream inStream = null;
        File pipConfigXml = new File(IdentityUtil.getIdentityConfigDirPath(), IdentityMgtConstants.PropertyConfig
                .CONFIG_FILE_NAME);
        if (pipConfigXml.exists()) {
            try {
                inStream = new FileInputStream(pipConfigXml);
                properties.load(inStream);
            } catch (FileNotFoundException e) {
                log.error("Can not load identity-mgt properties file ", e);
            } catch (IOException e) {
                log.error("Can not load identity-mgt properties file ", e);
            } finally {
                if (inStream != null) {
                    try {
                        inStream.close();
                    } catch (IOException e) {
                        log.error("Error while closing stream ", e);
                    }
                }
            }
        }
    }
}
