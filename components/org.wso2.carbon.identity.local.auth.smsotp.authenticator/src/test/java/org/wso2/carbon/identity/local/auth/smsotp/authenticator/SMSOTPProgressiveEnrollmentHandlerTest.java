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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.MobileNumberEnrollment;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.util.Utils;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Tests the mobile number details that the SMS OTP authenticator supplies to the shared enrollment handler.
 */
public class SMSOTPProgressiveEnrollmentHandlerTest {

    private SMSOTPProgressiveEnrollmentHandler handler;
    private Map<String, String> authenticatorParameters;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder;
    private MockedStatic<AuthenticatorUtils> authenticatorUtils;

    @BeforeMethod
    public void setUp() {

        authenticatorParameters = new HashMap<>();
        AuthenticatorConfig authenticatorConfig = mock(AuthenticatorConfig.class);
        when(authenticatorConfig.getParameterMap()).thenReturn(authenticatorParameters);
        FileBasedConfigurationBuilder configurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(configurationBuilder.getAuthenticatorBean(SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME))
                .thenReturn(authenticatorConfig);
        fileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        fileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(configurationBuilder);
        authenticatorUtils = mockStatic(AuthenticatorUtils.class);

        handler = new SMSOTPProgressiveEnrollmentHandler();
    }

    @AfterMethod
    public void tearDown() {

        fileBasedConfigurationBuilder.close();
        authenticatorUtils.close();
    }

    @Test
    public void testMobileNumberDetails() {

        assertEquals(handler.getValueClaimUri(), "http://wso2.org/claims/mobile");
        assertEquals(handler.getVerifiedClaimUri(), "http://wso2.org/claims/identity/phoneVerified");
        assertEquals(handler.getValueParameterName(), "MOBILE_NUMBER");
        // The message keys are read by the authentication portal.
        assertEquals(handler.getMessageKeyPrefix(), "sms.otp.mobile.number");
        assertEquals(handler.getDefaultValueRegex(), "^\\+?[0-9]{7,15}$");
        assertEquals(handler.getMaxValueLength(), 32);
    }

    @Test
    public void testOrganizationSettingsOfSmsOtpConnectorAreUsed() {

        assertEquals(handler.getEnrollmentEnabledSettingKey(), "SmsOTP.EnrolUserInAuthenticationFlow");
        assertEquals(handler.getValueRegexSettingKey(), "SmsOTP.MobileNumberRegex");
    }

    @DataProvider
    public Object[][] mobileNumbersToNormalize() {

        return new Object[][]{
                {" +94 77-123 4567 ", "+94771234567"},
                {"0771234567", "0771234567"},
                {"   ", null},
                {null, null}
        };
    }

    @Test(dataProvider = "mobileNumbersToNormalize")
    public void testWhitespacesAndHyphensAreRemoved(String submitted, String expected) {

        assertEquals(handler.normalize(submitted), expected);
    }

    @Test
    public void testSmsOtpSubmissionOrResendIsNotAMobileNumberSubmission() {

        AuthenticationContext context = new AuthenticationContext();
        context.setCurrentAuthenticator(SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME);
        context.setProperty(SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME + EnrollmentConstants.AWAITING_VALUE, true);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(SMSOTPConstants.MOBILE_NUMBER)).thenReturn("+94771234567");
        assertTrue(handler.isValueSubmission(request, context));

        when(request.getParameter(SMSOTPConstants.CODE)).thenReturn("123456");
        assertFalse(handler.isValueSubmission(request, context));

        HttpServletRequest resendRequest = mock(HttpServletRequest.class);
        when(resendRequest.getParameter(SMSOTPConstants.MOBILE_NUMBER)).thenReturn("+94771234567");
        when(resendRequest.getParameter(SMSOTPConstants.RESEND)).thenReturn("true");
        assertFalse(handler.isValueSubmission(resendRequest, context));
    }

    @DataProvider
    public Object[][] maxEnrollmentAttempts() {

        return new Object[][]{
                {null, MobileNumberEnrollment.DEFAULT_MAX_ENROLLMENT_ATTEMPTS},
                {"5", 5},
                {"0", MobileNumberEnrollment.DEFAULT_MAX_ENROLLMENT_ATTEMPTS},
                {"many", MobileNumberEnrollment.DEFAULT_MAX_ENROLLMENT_ATTEMPTS}
        };
    }

    @Test(dataProvider = "maxEnrollmentAttempts")
    public void testMaxEnrollmentAttempts(String configured, int expected) {

        if (configured != null) {
            authenticatorParameters.put(MobileNumberEnrollment.MAX_ENROLLMENT_ATTEMPTS_CONFIG, configured);
        }
        assertEquals(handler.getMaxEnrollmentAttempts(), expected);
    }

    @Test
    public void testConfiguredMobileNumberRequestPageIsUsed() throws Exception {

        authenticatorParameters.put(MobileNumberEnrollment.MOBILE_NUMBER_REQUEST_PAGE_URL_CONFIG,
                "authenticationendpoint/custom-mobile.jsp");
        authenticatorUtils.when(() -> AuthenticatorUtils.getMobileNumberRequestPageUrl(
                "authenticationendpoint/custom-mobile.jsp")).thenReturn("https://localhost/custom-mobile.jsp");

        assertEquals(handler.getEnrollmentPageUrl(), "https://localhost/custom-mobile.jsp");
    }

    @Test
    public void testConfiguredSmsOtpErrorPageIsUsed() throws Exception {

        authenticatorParameters.put(SMSOTPConstants.SMS_OTP_ERROR_PAGE_URL_CONFIG,
                "authenticationendpoint/custom-error.jsp");
        authenticatorUtils.when(() -> AuthenticatorUtils.getSMSOTPErrorPageUrl(anyString()))
                .thenAnswer(invocation -> "https://localhost/" + invocation.getArgument(0));

        assertEquals(handler.getErrorPageUrl(new AuthenticationContext()),
                "https://localhost/authenticationendpoint/custom-error.jsp");
    }

    @Test
    public void testOtpIsInvalidated() {

        AuthenticationContext context = new AuthenticationContext();
        context.setProperty(AuthenticatorConstants.OTP, "otp");
        context.setProperty(SMSOTPConstants.OTP_TOKEN, "otp");

        handler.invalidateOTP(context);

        assertNull(context.getProperty(AuthenticatorConstants.OTP));
        assertNull(context.getProperty(SMSOTPConstants.OTP_TOKEN));
    }

    @Test
    public void testSmsOtpVerificationOnUpdateIsSkippedAndCleared() {

        try (MockedStatic<Utils> recoveryUtils = mockStatic(Utils.class)) {
            handler.skipVerificationOnUpdate();
            recoveryUtils.verify(() -> Utils.setThreadLocalToSkipSendingSmsOtpVerificationOnUpdate(
                    IdentityRecoveryConstants.SkipMobileNumberVerificationOnUpdateStates.SKIP_ON_SMS_OTP_FLOW
                            .toString()));

            handler.clearVerificationSkip();
            recoveryUtils.verify(Utils::unsetThreadLocalToSkipSendingSmsOtpVerificationOnUpdate);
        }
    }
}
