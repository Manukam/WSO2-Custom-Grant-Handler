package org.wso2.sample.custom.grant.type;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

public class CustomGrantValidator extends AbstractValidator<HttpServletRequest> {
    public CustomGrantValidator() {

        // mobile number must be in the request parameter
        requiredParams.add(CustomGrantHandler.CLIENT_UUID_PARAM);
        requiredParams.add(CustomGrantHandler.AUTHORIZATION_CODE);
    }
}
