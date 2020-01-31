package org.wso2.sample.custom.grant.type;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

public class CustomGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final String CLIENT_UUID_PARAM = "uuidClient";
    private static Log log = LogFactory.getLog(CustomGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);

        OAuthAppDO appInfo;
        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        String uuidIS = null;
        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        String uuidClient = null;
        // find out Uuid Parameter
        for (RequestParameter parameter : parameters) {
            if (CLIENT_UUID_PARAM.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    uuidClient = parameter.getValue()[0];
                }
            }
        }

        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        try {
            appInfo = oAuthAppDAO.getAppInformation(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            if (appInfo.getApplicationName().equals("Playground_SP")) {    // Name of the Application

                uuidIS = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                        .getUserClaimValue(user.getUserName(), "http://wso2.org/claims/organization", null);
            }
        } catch (InvalidOAuthClientException e) {
            log.error(e);
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
}
