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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.MobileNumberEnrollment;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.CODE;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_MOBILE_NUMBER_REGEX;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.MOBILE_NUMBER;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME;

/**
 * Tests enrolling a mobile number during the authentication flow, for a user who does not have one configured.
 */
public class SMSOTPMobileNumberEnrollmentTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    private static final String MOBILE_NUMBER_REQUEST_PAGE = "https://localhost:9443/authenticationendpoint/mobile.jsp";
    private static final String ERROR_PAGE = "https://localhost:9443/authenticationendpoint/smsOtpError.jsp";
    private static final String MOBILE = "+94771234567";
    private static final String OTHER_MOBILE = "+94777654321";

    private SMSOTPAuthenticator authenticator;
    private AuthenticationContext context;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AbstractUserStoreManager userStoreManager;
    private Map<String, String> smsOtpConfigs;
    private Map<String, String> authenticatorParameters;
    private Map<String, String> userClaims;

    private MockedStatic<AuthenticatorUtils> authenticatorUtils;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<Utils> recoveryUtils;

    @BeforeMethod
    public void setUp() throws Exception {

        authenticator = new SMSOTPAuthenticator();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);

        smsOtpConfigs = new HashMap<>();
        smsOtpConfigs.put(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW, "true");
        authenticatorParameters = new HashMap<>();
        userClaims = new HashMap<>();

        authenticatorUtils = mockStatic(AuthenticatorUtils.class);
        authenticatorUtils.when(() -> AuthenticatorUtils.getSmsAuthenticatorConfig(anyString(), anyString()))
                .thenAnswer(invocation -> smsOtpConfigs.get(invocation.<String>getArgument(0)));
        authenticatorUtils.when(() -> AuthenticatorUtils.isAccountLocked(any(AuthenticatedUser.class)))
                .thenReturn(false);
        authenticatorUtils.when(() -> AuthenticatorUtils.getMobileNumberRequestPageUrl(any()))
                .thenReturn(MOBILE_NUMBER_REQUEST_PAGE);
        authenticatorUtils.when(() -> AuthenticatorUtils.getSMSOTPErrorPageUrl(any())).thenReturn(ERROR_PAGE);
        authenticatorUtils.when(() -> AuthenticatorUtils.getMultiOptionURIQueryParam(any())).thenReturn("");

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(any(), any(), any()))
                .thenReturn("sessionDataKey=session-data-key");
        frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0) + "?" + invocation.getArgument(1));

        AuthenticatorConfig authenticatorConfig = mock(AuthenticatorConfig.class);
        when(authenticatorConfig.getParameterMap()).thenReturn(authenticatorParameters);
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
    public void testRedirectToMobileNumberRequestPageForUserWithoutMobileNumber() throws Exception {

        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));

        String redirectUrl = captureRedirectUrl();
        assertTrue(redirectUrl.startsWith(MOBILE_NUMBER_REQUEST_PAGE));
        assertTrue(redirectUrl.contains("&authenticators=" + SMS_OTP_AUTHENTICATOR_NAME),
                "The authenticator is required on the page URL for app native authentication.");
        assertFalse(redirectUrl.contains("authFailure"), "No error is expected when requesting a number.");
        assertEquals(context.getProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER), true);
    }

    @Test
    public void testNoEnrollmentWhenDisabledForOrganization() throws Exception {

        smsOtpConfigs.put(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW, "false");

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentByDefault() throws Exception {

        smsOtpConfigs.remove(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testApplicationCanOptOutFromScript() throws Exception {

        Map<String, Map<String, String>> runtimeParams = new HashMap<>();
        runtimeParams.put(SMS_OTP_AUTHENTICATOR_NAME,
                Collections.singletonMap(MobileNumberEnrollment.ENROL_USER_IN_AUTHENTICATION_FLOW, "false"));
        context.addAuthenticatorParams(runtimeParams);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testApplicationCannotEnableFromScriptWhenDisabledForOrganization() throws Exception {

        smsOtpConfigs.put(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW, "false");
        Map<String, Map<String, String>> runtimeParams = new HashMap<>();
        runtimeParams.put(SMS_OTP_AUTHENTICATOR_NAME,
                Collections.singletonMap(MobileNumberEnrollment.ENROL_USER_IN_AUTHENTICATION_FLOW, "true"));
        context.addAuthenticatorParams(runtimeParams);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentWhenSmsOtpIsFirstFactor() throws Exception {

        context.setCurrentStep(1);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentForFederatedUser() throws Exception {

        AuthenticatedUser federatedUser = buildLocalUser();
        federatedUser.setFederatedUser(true);
        context = buildContext(federatedUser);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testNoEnrollmentForLockedUser() throws Exception {

        authenticatorUtils.when(() -> AuthenticatorUtils.isAccountLocked(any(AuthenticatedUser.class)))
                .thenReturn(true);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void testExistingMobileNumberIsNeverReplaced() throws Exception {

        userClaims.put(SMSOTPConstants.Claims.MOBILE_CLAIM, MOBILE);
        context.setProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(OTHER_MOBILE);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER),
                "A submitted number must not be considered for a user who already has a mobile number.");
        assertNull(context.getProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER));
    }

    @DataProvider
    public Object[][] invalidMobileNumbers() {

        return new Object[][]{
                {"abcdefgh"},
                {"12345"},
                {"+9477123456789012345"},
                {"+94771234567;+94777654321"},
                {"+947712345678901234567890123456789"}
        };
    }

    @Test(dataProvider = "invalidMobileNumbers")
    public void testInvalidMobileNumberIsRejectedBeforeSendingOtp(String mobileNumber) throws Exception {

        context.setProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(mobileNumber);

        // True means the flow does not continue to send an OTP.
        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));

        String redirectUrl = captureRedirectUrl();
        assertTrue(redirectUrl.startsWith(MOBILE_NUMBER_REQUEST_PAGE));
        assertTrue(redirectUrl.endsWith(MobileNumberEnrollment.ERROR_MOBILE_NUMBER_INVALID_QUERY_PARAMS));
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
    }

    @Test
    public void testValidMobileNumberIsKeptPendingUntilVerified() throws Exception {

        context.setProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);
        context.setRetrying(true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(" +94 77-123 4567 ");

        // False means the flow continues to send an OTP to the number.
        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));

        verify(response, never()).sendRedirect(anyString());
        assertEquals(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER), MOBILE);
        assertEquals(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS), 1);
        assertNull(context.getProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER));
        assertFalse(context.isRetrying(), "Failures of an earlier OTP must not be shown for the new number.");
        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testMobileNumberIsSubmittedOnlyWhileRequested() throws Exception {

        // A mobile number in a request which was not prompted for is not taken.
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(MOBILE);

        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));

        assertTrue(captureRedirectUrl().startsWith(MOBILE_NUMBER_REQUEST_PAGE));
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
    }

    @Test
    public void testMobileNumberIsNotTakenAlongWithOtpCode() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(OTHER_MOBILE);
        when(request.getParameter(CODE)).thenReturn("123456");

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        assertEquals(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER), MOBILE);
    }

    @Test
    public void testChangingNumberInvalidatesOtpSentToEarlierNumber() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS, 1);
        context.setProperty(AuthenticatorConstants.OTP, new OTP("123456", System.currentTimeMillis(), 300000));
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(OTHER_MOBILE);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));

        assertEquals(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER), OTHER_MOBILE);
        assertEquals(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS), 2);
        assertNull(context.getProperty(AuthenticatorConstants.OTP),
                "An OTP sent to an earlier number must not be able to verify the new number.");
        assertNull(context.getProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER));
    }

    @Test
    public void testResubmittingSameNumberDoesNotCountAsNewNumber() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS, 1);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(MOBILE);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        assertEquals(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS), 1);
    }

    @Test
    public void testNumberOfMobileNumbersPerFlowIsLimited() throws Exception {

        authenticatorParameters.put(MobileNumberEnrollment.MAX_ENROLLMENT_ATTEMPTS_CONFIG, "2");
        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS, 2);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(OTHER_MOBILE);

        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));

        String redirectUrl = captureRedirectUrl();
        assertTrue(redirectUrl.startsWith(ERROR_PAGE));
        assertTrue(redirectUrl.contains(MobileNumberEnrollment.ERROR_ENROLLMENT_ATTEMPTS_EXCEEDED_QUERY_PARAMS));
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
        assertEquals(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS), 2,
                "The count is kept so that the limit cannot be reset within the flow.");
    }

    @Test
    public void testExceedingNumberLimitInvalidatesOtpOfPendingNumber() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS,
                MobileNumberEnrollment.DEFAULT_MAX_ENROLLMENT_ATTEMPTS);
        context.setProperty(AuthenticatorConstants.OTP, new OTP("123456", System.currentTimeMillis(), 300000));
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(OTHER_MOBILE);

        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));

        assertNull(context.getProperty(AuthenticatorConstants.OTP),
                "The OTP must not complete the authentication once the enrollment is discontinued.");
    }

    @Test
    public void testDiscontinuedEnrollmentInvalidatesOtpOfPendingNumber() throws Exception {

        // A mobile number is configured for the user while an OTP sent to the pending number is not yet verified.
        userClaims.put(SMSOTPConstants.Claims.MOBILE_CLAIM, OTHER_MOBILE);
        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER, MOBILE);
        context.setProperty(AuthenticatorConstants.OTP, new OTP("123456", System.currentTimeMillis(), 300000));

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));

        assertNull(context.getProperty(AuthenticatorConstants.OTP),
                "An OTP sent to a number other than the configured number must not complete the authentication.");
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
    }

    @Test
    public void testOtpOfRegularFlowIsKeptForUserWithMobileNumber() throws Exception {

        userClaims.put(SMSOTPConstants.Claims.MOBILE_CLAIM, MOBILE);
        OTP otp = new OTP("123456", System.currentTimeMillis(), 300000);
        context.setProperty(AuthenticatorConstants.OTP, otp);

        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));

        assertEquals(context.getProperty(AuthenticatorConstants.OTP), otp);
    }

    @Test
    public void testConfiguredRegexIsEnforced() throws Exception {

        smsOtpConfigs.put(SMS_OTP_MOBILE_NUMBER_REGEX, "^\\+94[0-9]{9}$");
        context.setProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn("+14155552671");

        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));
        assertTrue(captureRedirectUrl().endsWith(MobileNumberEnrollment.ERROR_MOBILE_NUMBER_INVALID_QUERY_PARAMS));

        when(request.getParameter(MOBILE_NUMBER)).thenReturn(MOBILE);
        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        assertEquals(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER), MOBILE);
    }

    @Test
    public void testInvalidConfiguredRegexRejectsAllNumbers() throws Exception {

        smsOtpConfigs.put(SMS_OTP_MOBILE_NUMBER_REGEX, "^([0-9");
        context.setProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(MOBILE);

        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
    }

    @Test
    public void testOtpFlowContinuesForPendingNumber() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);

        // Resending or retrying the OTP continues as usual, for the number pending enrollment.
        assertFalse(authenticator.handleMobileNumberEnrollment(request, response, context));
        verify(response, never()).sendRedirect(anyString());
        assertEquals(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER), MOBILE);
    }

    @Test
    public void testEnrollmentErrorIsShownOnceOnMobileNumberRequestPage() throws Exception {

        context.setProperty(MobileNumberEnrollment.ENROLLMENT_ERROR,
                MobileNumberEnrollment.ERROR_ENROLLMENT_FAILED_QUERY_PARAMS);

        assertTrue(authenticator.handleMobileNumberEnrollment(request, response, context));

        assertTrue(captureRedirectUrl().endsWith(MobileNumberEnrollment.ERROR_ENROLLMENT_FAILED_QUERY_PARAMS));
        assertNull(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ERROR));
    }

    @Test
    public void testVerifiedMobileNumberIsSavedAsVerified() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS, 1);

        authenticator.completeMobileNumberEnrollment(context);

        ArgumentCaptor<Map<String, String>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(userStoreManager).setUserClaimValues(anyString(), claimsCaptor.capture(), isNull());
        Map<String, String> savedClaims = claimsCaptor.getValue();
        assertEquals(savedClaims.get(SMSOTPConstants.Claims.MOBILE_CLAIM), MOBILE);
        assertEquals(savedClaims.get(SMSOTPConstants.Claims.MOBILE_VERIFIED_CLAIM), "true");
        assertEquals(savedClaims.size(), 2);

        // A second verification of the number is skipped since it is already verified.
        recoveryUtils.verify(() -> Utils.setThreadLocalToSkipSendingSmsOtpVerificationOnUpdate(
                IdentityRecoveryConstants.SkipMobileNumberVerificationOnUpdateStates.SKIP_ON_SMS_OTP_FLOW
                        .toString()));
        recoveryUtils.verify(Utils::unsetThreadLocalToSkipSendingSmsOtpVerificationOnUpdate);

        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
        assertNull(context.getProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER));
        assertNull(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ATTEMPTS));
    }

    @Test
    public void testNumberIsNotSavedWhenOtpWasNotSentToIt() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, OTHER_MOBILE);
        context.setProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER, MOBILE);

        assertCompletionFails(SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_MOBILE_NUMBER.getCode());

        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
        assertEquals(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ERROR),
                MobileNumberEnrollment.ERROR_ENROLLMENT_FAILED_QUERY_PARAMS);
    }

    @Test
    public void testNumberIsNotSavedWithoutAnOtpSentToIt() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);

        assertCompletionFails(SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_MOBILE_NUMBER.getCode());
        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testMobileNumberConfiguredDuringEnrollmentIsNotReplaced() throws Exception {

        userClaims.put(SMSOTPConstants.Claims.MOBILE_CLAIM, OTHER_MOBILE);
        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER, MOBILE);

        assertCompletionFails(SMSOTPConstants.ErrorMessages.ERROR_CODE_MOBILE_NUMBER_ALREADY_CONFIGURED.getCode());
        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testFailureToSaveNumberIsReportedWithoutInternalDetails() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);
        context.setProperty(MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER, MOBILE);
        doThrow(new UserStoreClientException("Attribute value is not unique: internal detail"))
                .when(userStoreManager).setUserClaimValues(anyString(), anyMap(), isNull());

        assertCompletionFails(SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_MOBILE_NUMBER.getCode());

        // Only a fixed error key is shown to the user.
        assertEquals(context.getProperty(MobileNumberEnrollment.ENROLLMENT_ERROR),
                MobileNumberEnrollment.ERROR_ENROLLMENT_FAILED_QUERY_PARAMS);
        assertNull(context.getProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER));
        recoveryUtils.verify(Utils::unsetThreadLocalToSkipSendingSmsOtpVerificationOnUpdate);
    }

    @Test
    public void testNothingIsSavedWithoutPendingNumber() throws Exception {

        authenticator.completeMobileNumberEnrollment(context);

        verify(userStoreManager, never()).setUserClaimValues(anyString(), anyMap(), any());
    }

    @Test
    public void testOtpIsSentToPendingNumberOfUserWithoutMobileNumber() throws Exception {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);

        String maskedMobileNumber = authenticator.getMaskedUserClaimValue(buildLocalUser(), TENANT_DOMAIN, false,
                context);

        assertEquals(maskedMobileNumber, "********4567");
    }

    @Test
    public void testPendingNumberIsIgnoredForUserWithMobileNumber() throws Exception {

        userClaims.put(SMSOTPConstants.Claims.MOBILE_CLAIM, OTHER_MOBILE);
        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);

        String maskedMobileNumber = authenticator.getMaskedUserClaimValue(buildLocalUser(), TENANT_DOMAIN, false,
                context);

        assertEquals(maskedMobileNumber, "********4321");
    }

    @Test
    public void testMobileNumberSubmissionResolvesToInitialOtp() {

        context.setProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);
        context.setRetrying(true);
        when(request.getParameter(MOBILE_NUMBER)).thenReturn(MOBILE);

        assertEquals(authenticator.resolveScenario(request, context),
                AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP);
    }

    @Test
    public void testAppNativeAuthenticationRequestsMobileNumber() {

        context.setProperty(MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);

        AuthenticatorData authenticatorData = authenticator.getAuthInitiationData(context).orElse(null);

        assertNotNull(authenticatorData);
        assertEquals(authenticatorData.getRequiredParams(), Collections.singletonList(MOBILE_NUMBER));
        assertEquals(authenticatorData.getAuthParams().get(0).getName(), MOBILE_NUMBER);
    }

    @Test
    public void testAppNativeAuthenticationRequestsCodeOncePending() {

        context.setProperty(MobileNumberEnrollment.PENDING_MOBILE_NUMBER, MOBILE);

        AuthenticatorData authenticatorData = authenticator.getAuthInitiationData(context).orElse(null);

        assertNotNull(authenticatorData);
        assertFalse(authenticatorData.getRequiredParams().contains(MOBILE_NUMBER));
    }

    private void assertCompletionFails(String expectedErrorCode) {

        try {
            authenticator.completeMobileNumberEnrollment(context);
            fail("Expected the enrollment to fail.");
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(), expectedErrorCode);
        }
    }

    private String captureRedirectUrl() throws Exception {

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(response, atLeastOnce()).sendRedirect(urlCaptor.capture());
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

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(2);
        context.setCurrentAuthenticator(SMS_OTP_AUTHENTICATOR_NAME);
        return context;
    }
}
