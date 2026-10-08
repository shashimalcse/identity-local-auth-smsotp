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

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.enrollment.EnrollmentConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.MOBILE_NUMBER;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME;

/**
 * Tests that the SMS OTP authenticator enrolls a mobile number through the shared enrollment handler, for a user who
 * does not have one configured.
 */
public class SMSOTPMobileNumberEnrollmentTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    private static final String MOBILE_NUMBER_REQUEST_PAGE = "https://localhost:9443/authenticationendpoint/mobile.jsp";
    private static final String MOBILE = "+94771234567";
    private static final String OTHER_MOBILE = "+94777654321";
    private static final String PENDING_VALUE = SMS_OTP_AUTHENTICATOR_NAME + EnrollmentConstants.PENDING_VALUE;
    private static final String AWAITING_VALUE = SMS_OTP_AUTHENTICATOR_NAME + EnrollmentConstants.AWAITING_VALUE;

    private NotificationCapturingAuthenticator authenticator;
    private AuthenticationContext context;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AbstractUserStoreManager userStoreManager;
    private Map<String, String> smsOtpConfigs;
    private Map<String, String> userClaims;

    private MockedStatic<AuthenticatorUtils> authenticatorUtils;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<Utils> recoveryUtils;

    @BeforeMethod
    public void setUp() throws Exception {

        authenticator = new NotificationCapturingAuthenticator();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        smsOtpConfigs = new HashMap<>();
        smsOtpConfigs.put(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW, "true");
        userClaims = new HashMap<>();

        authenticatorUtils = mockStatic(AuthenticatorUtils.class);
        authenticatorUtils.when(() -> AuthenticatorUtils.getMobileNumberRequestPageUrl(any()))
                .thenReturn(MOBILE_NUMBER_REQUEST_PAGE);

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(any(), any(), any()))
                .thenReturn("sessionDataKey=session-data-key");
        frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));

        AuthenticatorConfig authenticatorConfig = mock(AuthenticatorConfig.class);
        when(authenticatorConfig.getParameterMap()).thenReturn(new HashMap<>());
        FileBasedConfigurationBuilder configurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(configurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        fileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        fileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(configurationBuilder);

        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        recoveryUtils = mockStatic(Utils.class);

        userStoreManager = mock(AbstractUserStoreManager.class);
        when(userStoreManager.getUserClaimValues(anyString(), any(String[].class), isNull()))
                .thenAnswer(invocation -> new HashMap<>(userClaims));
        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        RealmService realmService = mock(RealmService.class);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        AuthenticatorDataHolder.setRealmService(realmService);
        // The shared enrollment handler reads the user store and the settings through the OTP commons services.
        org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder.setRealmService(realmService);
        org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder.setAccountLockService(
                mock(AccountLockService.class));
        IdentityGovernanceService governanceService = mock(IdentityGovernanceService.class);
        when(governanceService.getConfiguration(any(String[].class), anyString())).thenAnswer(invocation -> {
            String settingKey = ((String[]) invocation.getArgument(0))[0];
            Property setting = new Property();
            setting.setName(settingKey);
            setting.setValue(smsOtpConfigs.get(settingKey));
            return new Property[]{setting};
        });
        org.wso2.carbon.identity.auth.otp.core.internal.AuthenticatorDataHolder.setIdentityGovernanceService(
                governanceService);

        context = buildContext(buildLocalUser());
    }

    @AfterMethod
    public void tearDown() {

        authenticatorUtils.close();
        frameworkUtils.close();
        fileBasedConfigurationBuilder.close();
        identityTenantUtil.close();
        loggerUtils.close();
        recoveryUtils.close();
    }

    @Test
    public void testUserWithoutMobileNumberIsRedirectedToMobileNumberRequestPage() throws Exception {

        assertTrue(authenticator.getEnrollmentHandler().handleInitiation(request, response, context));

        String redirectUrl = captureRedirectUrl();
        assertTrue(redirectUrl.startsWith(MOBILE_NUMBER_REQUEST_PAGE));
        assertTrue(redirectUrl.contains("&authenticators=" + SMS_OTP_AUTHENTICATOR_NAME));
    }

    @Test
    public void testNoEnrollmentByDefault() throws Exception {

        smsOtpConfigs.remove(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW);

        assertFalse(authenticator.getEnrollmentHandler().handleInitiation(request, response, context));
    }

    @Test
    public void testInvalidMobileNumberIsReportedWithSmsOtpMessageKey() throws Exception {

        context.setProperty(AWAITING_VALUE, true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn("not-a-number");

        assertTrue(authenticator.getEnrollmentHandler().handleInitiation(request, response, context));

        assertTrue(captureRedirectUrl().endsWith("&authFailure=true&authFailureMsg=sms.otp.mobile.number.invalid"));
    }

    @Test
    public void testOtpIsSentToAndBoundToPendingMobileNumber() throws Exception {

        context.setProperty(AWAITING_VALUE, true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn("+94 77-123 4567");
        assertFalse(authenticator.getEnrollmentHandler().handleInitiation(request, response, context));

        authenticator.sendOtp(buildLocalUser(), new OTP("123456", System.currentTimeMillis(), 300000), false,
                request, response, context);

        assertEquals(authenticator.sentTo, MOBILE);
        assertEquals(context.getProperty(SMS_OTP_AUTHENTICATOR_NAME + EnrollmentConstants.OTP_SENT_TO_VALUE), MOBILE);
    }

    @Test
    public void testVerifiedMobileNumberIsSavedWithoutSecondVerification() throws Exception {

        context.setProperty(PENDING_VALUE, MOBILE);
        authenticator.getEnrollmentHandler().recordOTPSent(context, MOBILE);

        authenticator.getEnrollmentHandler().completeEnrollment(context, true);

        ArgumentCaptor<Map<String, String>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(userStoreManager).setUserClaimValues(anyString(), claimsCaptor.capture(), isNull());
        assertEquals(claimsCaptor.getValue().get(SMSOTPConstants.Claims.MOBILE_CLAIM), MOBILE);
        assertEquals(claimsCaptor.getValue().get(SMSOTPConstants.Claims.MOBILE_VERIFIED_CLAIM), "true");
        recoveryUtils.verify(() -> Utils.setThreadLocalToSkipSendingSmsOtpVerificationOnUpdate(
                IdentityRecoveryConstants.SkipMobileNumberVerificationOnUpdateStates.SKIP_ON_SMS_OTP_FLOW
                        .toString()));
        recoveryUtils.verify(Utils::unsetThreadLocalToSkipSendingSmsOtpVerificationOnUpdate);
    }

    @Test
    public void testEnrollmentErrorsUseSmsOtpErrorCodePrefix() {

        context.setProperty(PENDING_VALUE, MOBILE);

        try {
            authenticator.getEnrollmentHandler().completeEnrollment(context, true);
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(),
                    "SMS-" + AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_VALUE.getCode());
            return;
        }
        throw new AssertionError("Expected the enrollment without an OTP sent to the number to fail.");
    }

    @Test
    public void testOtpIsSentToPendingNumberOfUserWithoutMobileNumber() throws Exception {

        context.setProperty(PENDING_VALUE, MOBILE);

        assertEquals(authenticator.getMaskedUserClaimValue(buildLocalUser(), TENANT_DOMAIN, false, context),
                "********4567");
    }

    @Test
    public void testPendingNumberIsIgnoredForUserWithMobileNumber() throws Exception {

        userClaims.put(SMSOTPConstants.Claims.MOBILE_CLAIM, OTHER_MOBILE);
        context.setProperty(PENDING_VALUE, MOBILE);

        assertEquals(authenticator.getMaskedUserClaimValue(buildLocalUser(), TENANT_DOMAIN, false, context),
                "********4321");
    }

    @Test
    public void testMobileNumberSubmissionResolvesToInitialOtp() {

        context.setProperty(AWAITING_VALUE, true);
        context.setRetrying(true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(MOBILE);

        assertEquals(authenticator.resolveScenario(request, context),
                AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP);
    }

    @Test
    public void testAppNativeAuthenticationRequestsMobileNumber() {

        context.setProperty(AWAITING_VALUE, true);

        AuthenticatorData authenticatorData = authenticator.getAuthInitiationData(context).orElse(null);

        assertNotNull(authenticatorData);
        assertEquals(authenticatorData.getRequiredParams(), Collections.singletonList(MOBILE_NUMBER));
        assertEquals(authenticatorData.getAuthParams().get(0).getName(), MOBILE_NUMBER);
    }

    @Test
    public void testAppNativeAuthenticationRequestsCodeOncePending() {

        context.setProperty(PENDING_VALUE, MOBILE);

        AuthenticatorData authenticatorData = authenticator.getAuthInitiationData(context).orElse(null);

        assertNotNull(authenticatorData);
        assertFalse(authenticatorData.getRequiredParams().contains(MOBILE_NUMBER));
    }

    private String captureRedirectUrl() throws Exception {

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(urlCaptor.capture());
        return urlCaptor.getValue();
    }

    private static AuthenticatedUser buildLocalUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("alice");
        user.setUserId("4b4414e1-916b-4475-aaee-6b0751c29ff6");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain(TENANT_DOMAIN);
        user.setFederatedUser(false);
        return user;
    }

    private static AuthenticationContext buildContext(AuthenticatedUser user) {

        StepConfig firstStep = new StepConfig();
        firstStep.setSubjectAttributeStep(true);
        firstStep.setAuthenticatedUser(user);
        Map<Integer, StepConfig> stepMap = new HashMap<>();
        stepMap.put(1, firstStep);
        stepMap.put(2, new StepConfig());
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepMap);
        sequenceConfig.setApplicationConfig(mock(ApplicationConfig.class));

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(2);
        context.setCurrentAuthenticator(SMS_OTP_AUTHENTICATOR_NAME);
        return context;
    }

    /**
     * Authenticator which records the number an SMS is sent to, instead of publishing the notification event.
     */
    private static class NotificationCapturingAuthenticator extends SMSOTPAuthenticator {

        private String sentTo;

        @Override
        protected void triggerEvent(String eventName, AuthenticatedUser authenticatedUser,
                                    Map<String, Object> eventProperties) {

            sentTo = (String) eventProperties.get(SMSOTPConstants.ATTRIBUTE_SMS_SENT_TO);
        }
    }
}
