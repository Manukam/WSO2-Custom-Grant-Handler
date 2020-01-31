package org.wso2.sample.custom.grant.type;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;


/**
 * This validate the mobile grant request.
 */
public class CustomGrantValidator extends AbstractValidator<HttpServletRequest> {


    public CustomGrantValidator() {

        // mobile number must be in the request parameter
        requiredParams.add(CustomGrantHandler.CLIENT_UUID_PARAM);
    }
}
