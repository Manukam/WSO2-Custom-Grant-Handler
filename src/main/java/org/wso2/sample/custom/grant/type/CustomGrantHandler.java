package org.wso2.sample.custom.grant.type;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.dao.*;

public class CustomGrantHandler extends AbstractAuthorizationGrantHandler {

    public static final String CLIENT_UUID_PARAM = "uuidClient";
    public static final String AUTHORIZATION_CODE_PARAM = "code";
    private static Log log = LogFactory.getLog(CustomGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String uuidClient = null;
        String authorizationCode = null;
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


        String uuidIS = null;

        try {
            uuidIS = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                    .getUserClaimValue(user.getUserName(), "http://wso2.org/claims/organization", null);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            e.printStackTrace();
        }

        //if(request.getParameter("uuidClient").isEmpty()){ //Checking if UUID sent by the user is null
        if (uuidClient != null) {//Checking if UUID sent by the user is null
            if (uuidIS != null) {
                if (uuidIS.equals(uuidClient)) {
                    return true;   //valid user from same device
                } else {
                    return false; //new device invalid user
                }
            } else {
                //Invalid Request
                throw new IdentityOAuth2Exception("Invalid User");
            }
        } else {
            //Invalid Request
            throw new IdentityOAuth2Exception("Invalid User");
        }

    }

    private AuthzCodeDO getPersistedAuthzCode(OAuth2AccessTokenReqDTO tokenReqDTO) throws IdentityOAuth2Exception {

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

        AuthorizationCodeValidationResult validationResult = OAuthTokenPersistenceFactory.getInstance()
                .getAuthorizationCodeDAO().validateAuthorizationCode(tokenReqDTO.getClientId(),
                        tokenReqDTO.getAuthorizationCode());
        if (validationResult != null) {
            if (!validationResult.isActiveCode()) {
                //revoking access token issued for authorization code as per RFC 6749 Section 4.1.2
                revokeExistingAccessTokens(validationResult.getTokenId(), validationResult.getAuthzCodeDO());
            }
            return validationResult.getAuthzCodeDO();
        } else {
            // This means an invalid authorization code was sent for validation. We return null since higher
            // layers expect a null value for an invalid authorization code.
            return null;
        }
    }

    private void revokeExistingAccessTokens(String tokenId, AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().revokeAccessToken(tokenId, authzCodeDO
                .getAuthorizedUser().toString());

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Validated authorization code(hashed): " + DigestUtils.sha256Hex(authzCodeDO
                        .getAuthorizationCode()) + " for client: " + authzCodeDO.getConsumerKey() + " is not active. " +
                        "So revoking the access tokens issued for the authorization code.");
            } else {
                log.debug("Validated authorization code for client: " + authzCodeDO.getConsumerKey() + " is not " +
                        "active. So revoking the access tokens issued for the authorization code.");
            }
        }
    }
}
