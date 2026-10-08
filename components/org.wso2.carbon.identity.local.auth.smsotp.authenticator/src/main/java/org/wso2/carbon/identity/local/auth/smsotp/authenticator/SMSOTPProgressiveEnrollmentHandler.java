/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.local.auth.smsotp.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.enrollment.AbstractOTPProgressiveEnrollmentHandler;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.MobileNumberEnrollment;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.util.Utils;

/**
 * Lets a user who does not have a mobile number enroll one during the authentication flow, by verifying the SMS OTP
 * sent to that number.
 */
public class SMSOTPProgressiveEnrollmentHandler extends AbstractOTPProgressiveEnrollmentHandler {

    public SMSOTPProgressiveEnrollmentHandler() {

        super(SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME, "SMS", SMSOTPConstants.LogConstants.SMS_OTP_SERVICE);
    }

    @Override
    protected String getValueClaimUri() {

        return SMSOTPConstants.Claims.MOBILE_CLAIM;
    }

    @Override
    protected String getVerifiedClaimUri() {

        return SMSOTPConstants.Claims.MOBILE_VERIFIED_CLAIM;
    }

    @Override
    protected String getValueParameterName() {

        return SMSOTPConstants.MOBILE_NUMBER;
    }

    @Override
    protected String getValueParameterDisplayName() {

        return MobileNumberEnrollment.DISPLAY_MOBILE_NUMBER;
    }

    @Override
    protected String getValueParameterI18nKey() {

        return MobileNumberEnrollment.MOBILE_NUMBER_PARAM_KEY;
    }

    @Override
    protected String getMessageKeyPrefix() {

        return MobileNumberEnrollment.MESSAGE_KEY_PREFIX;
    }

    @Override
    protected String getEnrollmentEnabledSettingKey() {

        return SMSOTPConstants.ConnectorConfig.SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW;
    }

    @Override
    protected String getValueRegexSettingKey() {

        return SMSOTPConstants.ConnectorConfig.SMS_OTP_MOBILE_NUMBER_REGEX;
    }

    @Override
    protected String getDefaultValueRegex() {

        return MobileNumberEnrollment.DEFAULT_MOBILE_NUMBER_REGEX;
    }

    @Override
    protected String getEnrollmentPageUrl() throws AuthenticationFailedException {

        return AuthenticatorUtils.getMobileNumberRequestPageUrl(
                getAuthenticatorParameter(MobileNumberEnrollment.MOBILE_NUMBER_REQUEST_PAGE_URL_CONFIG));
    }

    @Override
    protected String getErrorPageUrl(AuthenticationContext context) throws AuthenticationFailedException {

        return AuthenticatorUtils.getSMSOTPErrorPageUrl(
                getAuthenticatorParameter(SMSOTPConstants.SMS_OTP_ERROR_PAGE_URL_CONFIG));
    }

    @Override
    protected void invalidateOTP(AuthenticationContext context) {

        context.removeProperty(AuthenticatorConstants.OTP);
        context.removeProperty(SMSOTPConstants.OTP_TOKEN);
    }

    /**
     * Skip the verification which is otherwise initiated on mobile number updates when mobile number verification is
     * enabled, since the number is already verified by the SMS OTP.
     */
    @Override
    protected void skipVerificationOnUpdate() {

        Utils.setThreadLocalToSkipSendingSmsOtpVerificationOnUpdate(
                IdentityRecoveryConstants.SkipMobileNumberVerificationOnUpdateStates.SKIP_ON_SMS_OTP_FLOW.toString());
    }

    @Override
    protected void clearVerificationSkip() {

        Utils.unsetThreadLocalToSkipSendingSmsOtpVerificationOnUpdate();
    }

    /**
     * Remove whitespaces and hyphens, which are commonly used to format mobile numbers.
     *
     * @param value Mobile number submitted by the user.
     * @return Mobile number without formatting characters, or null if blank.
     */
    @Override
    protected String normalize(String value) {

        if (StringUtils.isBlank(value)) {
            return null;
        }
        return value.replaceAll("[\\s-]", StringUtils.EMPTY);
    }

    @Override
    protected int getMaxValueLength() {

        return MobileNumberEnrollment.MAX_MOBILE_NUMBER_LENGTH;
    }

    @Override
    protected int getMaxEnrollmentAttempts() {

        String maxAttempts = getAuthenticatorParameter(MobileNumberEnrollment.MAX_ENROLLMENT_ATTEMPTS_CONFIG);
        if (NumberUtils.isDigits(maxAttempts) && Integer.parseInt(maxAttempts) > 0) {
            return Integer.parseInt(maxAttempts);
        }
        return MobileNumberEnrollment.DEFAULT_MAX_ENROLLMENT_ATTEMPTS;
    }
}
