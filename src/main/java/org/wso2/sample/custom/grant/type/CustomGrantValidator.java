package org.wso2.sample.custom.grant.type;

import org.wso2.carbon.identity.oauth2.validators.grant.AuthorizationCodeGrantValidator;



/**
 * This validate the mobile grant request.
 */
public class CustomGrantValidator extends AuthorizationCodeGrantValidator{

    public CustomGrantValidator() {
    }
}
