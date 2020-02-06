package org.wso2.sample.custom.grant.type;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.mgt.constants.IdentityMgtConstants;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationCodeGrantHandler;

import java.io.*;
import java.util.Properties;

public class CustomGrantHandler extends AuthorizationCodeGrantHandler {

    private static final String CLIENT_UUID_PARAM = "uuidClient";
    private static final String AUTHORIZATION_CODE_PARAM = "code";
    private static Properties properties = new Properties();
    private static Log log = LogFactory.getLog(CustomGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        for (RequestParameter parameter : tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters()) {
            if (AUTHORIZATION_CODE_PARAM.equals(parameter.getKey())) {
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAuthorizationCode(parameter.getValue()[0]);
                break;
            }
        }
        tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAuthorizationCode(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters()[0].getValue()[0].toString());
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
        String authorizationCode = null;
        String uuidIS ; //UUID in IS side
        // find out Uuid Parameter
        for (RequestParameter parameter : parameters) {
            if (CLIENT_UUID_PARAM.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    uuidClient = parameter.getValue()[0];
                }
            } else if (AUTHORIZATION_CODE_PARAM.equals(parameter.getKey())) {
                authorizationCode = parameter.getValue()[0];
            }
        }

        tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAuthorizationCode(authorizationCode);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        AuthzCodeDO authzCodeBean = getPersistedAuthzCode(tokenReq);
        AuthenticatedUser user = authzCodeBean.getAuthorizedUser();
        tokReqMsgCtx.setAuthorizedUser(user);
        tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());

        try {
            uuidIS = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                    .getUserClaimValue(user.getUserName(), singleDeviceClaim, null);
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

    private AuthzCodeDO getPersistedAuthzCode(OAuth2AccessTokenReqDTO tokenReqDTO) {

        AuthzCodeDO authzCodeDO;
        // If cache is enabled, check in the cache first.
        if (cacheEnabled) {
            OAuthCacheKey cacheKey = new OAuthCacheKey(OAuth2Util.buildCacheKeyStringForAuthzCode(
                    tokenReqDTO.getClientId(), tokenReqDTO.getAuthorizationCode()));
            authzCodeDO = (AuthzCodeDO) OAuthCache.getInstance().getValueFromCache(cacheKey);
            if (authzCodeDO != null) {
                return authzCodeDO;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authorization Code Info was not available in cache for client id : "
                            + tokenReqDTO.getClientId());
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization code information from db for client id : " + tokenReqDTO.getClientId());
        }

        return null;
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
