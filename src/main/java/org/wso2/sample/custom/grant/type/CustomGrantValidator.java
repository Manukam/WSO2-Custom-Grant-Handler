package org.wso2.sample.custom.grant.type;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;
import org.wso2.carbon.identity.oauth2.validators.grant.AuthorizationCodeGrantValidator;

import javax.servlet.http.HttpServletRequest;


/**
 * This validate the mobile grant request.
 */
public class CustomGrantValidator extends AuthorizationCodeGrantValidator{


    public CustomGrantValidator() {
        // device id must be in the request parameter
        this.requiredParams.add(CustomGrantHandler.CLIENT_UUID_PARAM);
    }
}
