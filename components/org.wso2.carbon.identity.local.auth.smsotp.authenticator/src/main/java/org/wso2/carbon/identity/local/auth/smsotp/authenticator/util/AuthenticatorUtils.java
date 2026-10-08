/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.smsotp.authenticator.util;

import org.apache.commons.lang.StringUtils;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.exception.SMSOTPAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.internal.AuthenticatorDataHolder;

import javax.servlet.http.HttpServletRequest;

/**
 * This class contains the utility method implementations.
 */
public class AuthenticatorUtils {

    /**
     * Check whether a given user account is locked.
     *
     * @param user Authenticated user.
     * @return True if user account is locked.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    public static boolean isAccountLocked(AuthenticatedUser user) throws AuthenticationFailedException {

        try {
            return AuthenticatorDataHolder.getAccountLockService().isAccountLocked(user.getUserName(),
                    user.getTenantDomain(), user.getUserStoreDomain());
        } catch (AccountLockServiceException e) {
            String error = String.format(SMSOTPConstants.ErrorMessages.ERROR_CODE_GETTING_ACCOUNT_STATE.getMessage(),
                    user.getUserName());
            throw new AuthenticationFailedException(SMSOTPConstants.ErrorMessages
                    .ERROR_CODE_GETTING_ACCOUNT_STATE.getCode(), error, e);
        }
    }

    /**
     * Get sms authenticator config related to the given key.
     *
     * @param key          Authenticator config key.
     * @param tenantDomain Tenant domain.
     * @return Value associated with the given config key.
     * @throws SMSOTPAuthenticatorServerException If an error occurred while getting th config value.
     */
    public static String getSmsAuthenticatorConfig(String key, String tenantDomain)
            throws SMSOTPAuthenticatorServerException {

        try {
            Property[] connectorConfigs;
            IdentityGovernanceService governanceService = AuthenticatorDataHolder.getIdentityGovernanceService();
            connectorConfigs = governanceService.getConfiguration(new String[]{key}, tenantDomain);
            if (connectorConfigs == null || connectorConfigs.length == 0) {
                return null;
            }
            return connectorConfigs[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw handleServerException(SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG, e,
                    (Object) null);
        }
    }

    /**
     * Get sms OTP login page URL.
     *
     * @return URL of the OTP login page.
     * @throws AuthenticationFailedException If an error occurred while getting the login page url.
     */
    public static String getSMSOTPLoginPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create().addPath(SMSOTPConstants.SMS_OTP_PAGE).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building sms OTP login page URL", e);
        }
    }

    /**
     * Get sms OTP login page URL.
     *
     * @param otpPageUrl SMS OTP Page URL.
     * @return URL of the OTP login page.
     * @throws AuthenticationFailedException If an error occurred while getting the login page url.
     */
    public static String getSMSOTPLoginPageUrl(String otpPageUrl) throws AuthenticationFailedException {

        try {
            if (StringUtils.isBlank(otpPageUrl)) {
                return getSMSOTPLoginPageUrl();
            }
            return ServiceURLBuilder.create().addPath(otpPageUrl).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building sms OTP login page URL", e);
        }
    }

    /**
     * Get SMS OTP error page URL.
     *
     * @return URL of the OTP error page.
     * @throws AuthenticationFailedException If an error occurred while getting the error page url.
     */
    public static String getSMSOTPErrorPageUrl() throws AuthenticationFailedException {

        try {
            return ServiceURLBuilder.create().addPath(SMSOTPConstants.ERROR_PAGE).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building sms OTP error page URL", e);
        }
    }

    /**
     * Get SMS OTP error page URL.
     *
     * @param errorPageUrl SMS OTP error page URL.
     * @return URL of the OTP error page.
     * @throws AuthenticationFailedException If an error occurred while getting the error page url.
     */
    public static String getSMSOTPErrorPageUrl(String errorPageUrl) throws AuthenticationFailedException {

        try {
            if (StringUtils.isBlank(errorPageUrl)) {
                return getSMSOTPErrorPageUrl();
            }
            return ServiceURLBuilder.create().addPath(errorPageUrl).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building sms OTP login page URL", e);
        }
    }

    /**
     * Get the mobile number request page URL.
     *
     * @param mobileNumberRequestPageUrl Configured page URL. The default page is used when blank.
     * @return URL of the mobile number request page.
     * @throws AuthenticationFailedException If an error occurred while building the URL.
     */
    public static String getMobileNumberRequestPageUrl(String mobileNumberRequestPageUrl)
            throws AuthenticationFailedException {

        String pageUrl = StringUtils.isBlank(mobileNumberRequestPageUrl) ?
                SMSOTPConstants.MobileNumberEnrollment.MOBILE_NUMBER_REQUEST_PAGE : mobileNumberRequestPageUrl;
        try {
            return ServiceURLBuilder.create().addPath(pageUrl).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building mobile number request page URL", e);
        }
    }

    /**
     * Get the SmsOtpAuthenticatorServerException with given error details.
     *
     * @param error     ErrorMessages.
     * @param throwable Throwable.
     * @param data      Meta data.
     * @return SmsOtpAuthenticatorServerException.
     */
    public static SMSOTPAuthenticatorServerException handleServerException(SMSOTPConstants.ErrorMessages error,
                                                                           Throwable throwable, Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        return new SMSOTPAuthenticatorServerException(error.getCode(), message, throwable);
    }

    /**
     * Get the multi option URI query params.
     *
     * @param request HttpServletRequest.
     * @return Multi option URI query parameter value.
     */
    public static String getMultiOptionURIQueryParam(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter("multiOptionURI");
            multiOptionURI = multiOptionURI != null ? SMSOTPConstants.MULTI_OPTION_URI_PARAM +
                    Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }
}
