/*
 * Copyright (c) 2023-2026, WSO2 LLC. (https://www.wso2.com).
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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.auth.otp.core.AbstractOTPAuthenticator;
import org.wso2.carbon.identity.auth.otp.core.PasswordlessOTPAuthenticator;
import org.wso2.carbon.identity.auth.otp.core.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.auth.otp.core.model.OTPResendClaims;
import org.wso2.carbon.identity.captcha.connector.recaptcha.AbstractOTPCaptchaConnector;
import org.wso2.carbon.identity.captcha.connector.recaptcha.LocalSMSOTPCaptchaConnector;
import org.wso2.carbon.identity.captcha.exception.CaptchaException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.exception.SMSOTPAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.smsotp.authenticator.util.AuthenticatorUtils;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_FEATURE_NOT_ENABLED;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.CODE;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.Claims.SMS_OTP_LAST_SENT_TIME_CLAIM;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.Claims.SMS_OTP_RESEND_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.DISPLAY_CODE;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.DISPLAY_USERNAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.RESEND;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_AUTHENTICATION_ENDPOINT_URL_CONFIG;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_ERROR_PAGE_URL_CONFIG;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_RESEND_ATTEMPTS_PROPERTY_NAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.SMS_OTP_RETRY_ATTEMPTS_PROPERTY_NAME;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.USERNAME;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * This class contains the implementation of sms OTP authenticator.
 */
public class SMSOTPAuthenticator extends AbstractOTPAuthenticator implements LocalApplicationAuthenticator,
        PasswordlessOTPAuthenticator {

    private static final Log LOG = LogFactory.getLog(SMSOTPAuthenticator.class);
    private static final long serialVersionUID = 850244886656426295L;

    private static final String SMS_OTP_SENT = "SMSOTPSent";
    private static final String MASKED_MOBILE_NUMBER = "maskedMobileNumber";

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Inside SMSOTPAuthenticator canHandle method and check the existence of mobile number and " +
                    "otp code");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(RESEND))
                && StringUtils.isEmpty(request.getParameter(CODE)))
                || StringUtils.isNotEmpty(request.getParameter(CODE))
                || StringUtils.isNotEmpty(request.getParameter(SMSOTPConstants.MOBILE_NUMBER))
                || (StringUtils.isNotEmpty(request.getParameter(USERNAME))
                && StringUtils.isEmpty(request.getParameter(SMSOTPConstants.PASSWORD))));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getRequestedSessionId();
    }

    @Override
    public String getFriendlyName() {

        return SMSOTPConstants.SMS_OTP_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return SMSOTPConstants.SMS_OTP_AUTHENTICATOR_NAME;
    }

    @Override
    public AuthenticatorConstants.AuthenticationScenarios resolveScenario(HttpServletRequest request,
            AuthenticationContext context) {

        // If the current authenticator is not SMS OTP, then set the flow to not retrying which could have been
        // set from other authenticators and not cleared.
        if (!SMS_OTP_AUTHENTICATOR_NAME.equals(context.getCurrentAuthenticator())) {
            context.setRetrying(false);
        }
        if (context.isLogoutRequest()) {
            return AuthenticatorConstants.AuthenticationScenarios.LOGOUT;
        } else if (isMobileNumberSubmission(request, context)) {
            // A mobile number submitted for enrollment initiates sending an OTP to that number.
            return AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP;
        } else if (!SMS_OTP_AUTHENTICATOR_NAME.equals(context.getCurrentAuthenticator()) ||
                !context.isRetrying() && StringUtils.isBlank(request.getParameter(CODE)) &&
                !Boolean.parseBoolean(request.getParameter(RESEND))) {
            return AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP;
        } else {
            return context.isRetrying() &&
                    Boolean.parseBoolean(request.getParameter(RESEND)) ?
                    AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP :
                    AuthenticatorConstants.AuthenticationScenarios.SUBMIT_OTP;
        }
    }

    @Override
    public int getOTPLength(String tenantDomain) throws AuthenticationFailedException {

        try {
            String configuredOTPLength = AuthenticatorUtils
                    .getSmsAuthenticatorConfig(SMSOTPConstants.ConnectorConfig.SMS_OTP_LENGTH, tenantDomain);
            if (NumberUtils.isNumber(configuredOTPLength)) {
                return Integer.parseInt(configuredOTPLength);
            }
            return SMSOTPConstants.DEFAULT_OTP_LENGTH;
        } catch (SMSOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    private boolean isNotifySmsSendingFailureEnabled(String tenantDomain) throws AuthenticationFailedException {

        try {
            String config = AuthenticatorUtils
                    .getSmsAuthenticatorConfig(SMSOTPConstants.ConnectorConfig.SMS_OTP_NOTIFY_SMS_SENDING_FAILURE,
                            tenantDomain);
            return Boolean.parseBoolean(config);
        } catch (SMSOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    @Override
    public boolean retryAuthenticationEnabled() {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        if (MapUtils.isNotEmpty(parameterMap)) {
            return Boolean.parseBoolean(parameterMap.get(ENABLE_RETRY_FROM_AUTHENTICATOR));
        }
        return true;
    }

    @Override
    protected String getAuthenticatorErrorPrefix() {
        return "SMS";
    }

    @Override
    protected String getErrorPageURL(AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        return AuthenticatorUtils.getSMSOTPErrorPageUrl(
                getAuthenticatorConfig().getParameterMap().get(SMS_OTP_ERROR_PAGE_URL_CONFIG));
    }

    @Override
    protected String getMaskedUserClaimValue(AuthenticatedUser authenticatedUser, String tenantDomain,
                                             boolean isInitialFederationAttempt,
                                             AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String mobile = resolveMobileNoOfAuthenticatedUser(authenticatedUser, tenantDomain, authenticationContext,
                isInitialFederationAttempt);
        if (StringUtils.isBlank(mobile)) {
            return null;
        }
        int screenAttributeLength = mobile.length();
        String screenValue = mobile.substring(screenAttributeLength - SMSOTPConstants.MASKED_DIGITS,
                screenAttributeLength);
        String hiddenScreenValue = mobile.substring(0, screenAttributeLength - SMSOTPConstants.MASKED_DIGITS);
        screenValue = new String(new char[hiddenScreenValue.length()]).
                replace("\0", SMSOTPConstants.MOBILE_NUMBER_MASKING_CHARACTER).concat(screenValue);
        return screenValue;
    }

    @Override
    protected String getOTPLoginPageURL(AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        return AuthenticatorUtils.getSMSOTPLoginPageUrl(
                getAuthenticatorConfig().getParameterMap().get(SMS_OTP_AUTHENTICATION_ENDPOINT_URL_CONFIG));
    }

    @Override
    protected String getOTPFailedAttemptsClaimUri() throws AuthenticationFailedException {

        return SMSOTPConstants.Claims.SMS_OTP_FAILED_ATTEMPTS_CLAIM;
    }

    @Override
    protected String getRemainingNumberOfOtpAttemptsQueryParam() {

        return SMSOTPConstants.REMAINING_NUMBER_OF_SMS_OTP_ATTEMPTS_QUERY;
    }

    @Override
    protected boolean isShowAuthFailureReason() {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String showAuthFailureReason = parameterMap.get(SMSOTPConstants.CONF_SHOW_AUTH_FAILURE_REASON);
        return Boolean.parseBoolean(showAuthFailureReason);
    }

    @Override
    protected long getOtpValidityPeriodInMillis(String tenantDomain) throws AuthenticationFailedException {

        try {
            String value = AuthenticatorUtils.getSmsAuthenticatorConfig(SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME,
                    tenantDomain);
            if (StringUtils.isBlank(value)) {
                return SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
            }
            long validityTime;
            try {
                validityTime = Long.parseLong(value);
            } catch (NumberFormatException e) {
                LOG.error(String.format("SMS OTP validity period value: %s configured in tenant : %s is not a " +
                                "number. Therefore, default validity period: %s (milli-seconds) will be used", value,
                        tenantDomain, SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS));
                return SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
            }
            // We don't need to send tokens with infinite validity.
            if (validityTime < 0) {
                LOG.error(String.format("SMS OTP validity period value: %s configured in tenant : %s cannot be a " +
                        "negative number. Therefore, default validity period: %s (milli-seconds) will " +
                        "be used", value, tenantDomain, SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS));
                return SMSOTPConstants.DEFAULT_SMS_OTP_VALIDITY_IN_MILLIS;
            }
            // Converting to milliseconds since the config is provided in seconds.
            return validityTime * 1000;
        } catch (SMSOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG,
                    exception);
        }
    }

    @Override
    protected void publishPostOTPGeneratedEvent(OTP otp, AuthenticatedUser authenticatedUser,
                                                HttpServletRequest httpServletRequest,
                                                AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String tenantDomain = authenticationContext.getTenantDomain();
        Map<String, Object> eventProperties = new HashMap<>();

        try {
            eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID,
                    authenticationContext.getCallerSessionKey());
            eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_ID,
                    getApplicationId(authenticationContext.getServiceProviderName(),
                            authenticationContext.getTenantDomain()));
            eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID,
                    IdentityTenantUtil.getTenantId(tenantDomain));
            eventProperties.put(SMSOTPConstants.PROVIDER, getProviderType(tenantDomain));
            eventProperties.put(IdentityEventConstants.EventProperty.USER_ID, authenticatedUser.getUserId());
            eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN,
                    authenticatedUser.getUserStoreDomain());
            if (StringUtils.isNotBlank(httpServletRequest.getParameter(RESEND))) {
                eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE,
                        httpServletRequest.getParameter(RESEND));
            } else {
                eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, false);
            }
            // Add OTP generated time and OTP expiry time to the event.
            Object otpGeneratedTimeProperty = authenticationContext.getProperty(SMSOTPConstants.OTP_GENERATED_TIME);
            if (otpGeneratedTimeProperty != null) {
                long otpGeneratedTime = (long) otpGeneratedTimeProperty;
                eventProperties.put(SMSOTPConstants.OTP_GENERATED_TIME, otpGeneratedTime);

                // Calculate OTP expiry time.
                long expiryTime = otpGeneratedTime + getOtpValidityPeriodInMillis(tenantDomain);
                eventProperties.put(SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME, expiryTime);
            }
        } catch (UserIdNotFoundException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_USER_ID_NOT_FOUND,
                    e, (Object) null);
        }
        triggerEvent(IdentityEventConstants.Event.POST_GENERATE_SMS_OTP, authenticatedUser, eventProperties);
    }

    @Override
    protected void publishPostOTPValidatedEvent(OTP otp, AuthenticatedUser authenticatedUser,
                                                boolean isAuthenticationPassed, boolean isExpired,
                                                HttpServletRequest httpServletRequest,
                                                AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String tenantDomain = authenticationContext.getTenantDomain();

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID,
                authenticationContext.getCallerSessionKey());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME,
                authenticationContext.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_INPUT_OTP,
                httpServletRequest.getParameter(CODE));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_USED_TIME, System.currentTimeMillis());
        // Add otp status to the event properties.
        if (isAuthenticationPassed) {
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS, SMSOTPConstants.STATUS_SUCCESS);
            eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP,
                    httpServletRequest.getParameter(CODE));
        } else {
            if (isExpired) {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        SMSOTPConstants.STATUS_OTP_EXPIRED);
                // Add generated time and expiry time info for the event.
                long otpGeneratedTime = (long) authenticationContext.getProperty(SMSOTPConstants.OTP_GENERATED_TIME);
                eventProperties.put(SMSOTPConstants.OTP_GENERATED_TIME, otpGeneratedTime);
                long expiryTime = otpGeneratedTime + getOtpValidityPeriodInMillis(tenantDomain);
                eventProperties.put(SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME, expiryTime);
            } else {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        SMSOTPConstants.STATUS_CODE_MISMATCH);
            }
        }
        triggerEvent(IdentityEventConstants.Event.POST_VALIDATE_SMS_OTP, authenticatedUser, eventProperties);
    }

    @Override
    protected void sendOtp(AuthenticatedUser authenticatedUser, OTP otp, boolean isInitialFederationAttempt,
                           HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                           AuthenticationContext authenticationContext) throws AuthenticationFailedException {

        authenticationContext.setProperty(SMSOTPConstants.OTP_TOKEN, otp);
        authenticationContext.setProperty(SMSOTPConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        authenticationContext.setProperty(SMSOTPConstants.OTP_EXPIRED, Boolean.toString(false));

        String tenantDomain = authenticationContext.getTenantDomain();
        String mobileNumber = resolveMobileNoOfAuthenticatedUser(authenticatedUser, tenantDomain,
                authenticationContext, isInitialFederationAttempt);
        if (StringUtils.isNotBlank(getPendingMobileNumber(authenticationContext))) {
            // Binds the OTP to the number it is sent to, so that only that number can be enrolled with the OTP.
            authenticationContext.setProperty(SMSOTPConstants.MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER,
                    mobileNumber);
        }

        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        metaProperties.put(SMSOTPConstants.ATTRIBUTE_SMS_SENT_TO, mobileNumber);
        metaProperties.put(SMSOTPConstants.OTP_TOKEN, otp);
        metaProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME,
                authenticationContext.getServiceProviderName());
        metaProperties.put(SMSOTPConstants.ConnectorConfig.OTP_EXPIRY_TIME,
                String.valueOf(getOtpValidityPeriodInMillis(authenticationContext.getTenantDomain()) / 60000));
        metaProperties.put(SMSOTPConstants.TEMPLATE_TYPE, SMSOTPConstants.EVENT_NAME);
        /*
         Reading the SMS Template type from the runtime params if exists which is set from the
         authentication script.
        */
        Map<String, String> smsOtpAuthenticatorParams = getRuntimeParams(authenticationContext);
        String smsTemplateType = smsOtpAuthenticatorParams.get(SMSOTPConstants.SMS_TEMPLATE_TYPE);
        if (StringUtils.isNotEmpty(smsTemplateType)) {
            metaProperties.put(SMSOTPConstants.TEMPLATE_TYPE, smsTemplateType);
        }
        String maskedMobileNumber = getMaskedUserClaimValue(authenticatedUser, tenantDomain, isInitialFederationAttempt,
                authenticationContext);
        setAuthenticatorMessage(authenticationContext, maskedMobileNumber);
        if (isNotifySmsSendingFailureEnabled(tenantDomain)) {
            metaProperties.put(SMSOTPConstants.NOTIFY_SPECIFIC_PROVIDER_FAILURES, Boolean.TRUE.toString());
        }
        /* SaaS apps are created at the super tenant level and they can be accessed by users of other organizations.
        If users of other organizations try to login to a saas app, the sms notification should be triggered from the
        sms provider configured for that organization. Hence, we need to start a new tenanted flow here. */
        if (authenticationContext.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
            try {
                FrameworkUtils.startTenantFlow(authenticatedUser.getTenantDomain());
                triggerOtpEvent(SMSOTPConstants.EVENT_TRIGGER_NAME, authenticatedUser, metaProperties,
                        authenticationContext);
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        } else {
            triggerOtpEvent(SMSOTPConstants.EVENT_TRIGGER_NAME, authenticatedUser, metaProperties,
                    authenticationContext);
        }
    }

    protected void triggerOtpEvent(String eventName, AuthenticatedUser authenticatedUser,
            Map<String, Object> eventProperties) throws AuthenticationFailedException {

        /* The notification request is recorded here rather than in the overload below, so that a send made by an
         extended authenticator which calls this overload directly also leaves evidence of the request. */
        try {
            triggerEvent(eventName, authenticatedUser, eventProperties);
            logSmsOtpNotificationRequest("SMS OTP send request was successfully initiated to the SMS provider.",
                    authenticatedUser, eventProperties, null, DiagnosticLog.ResultStatus.SUCCESS);
        } catch (AuthenticationFailedException e) {
            logSmsOtpNotificationRequest("SMS OTP send request to the SMS provider failed.", authenticatedUser,
                    eventProperties, resolveProviderErrorCode(e), DiagnosticLog.ResultStatus.FAILED);
            throw e;
        }
    }

    protected void triggerOtpEvent(String eventName, AuthenticatedUser authenticatedUser,
            Map<String, Object> eventProperties, AuthenticationContext context) throws AuthenticationFailedException {

        try {
            triggerOtpEvent(eventName, authenticatedUser, eventProperties);
        } catch (AuthenticationFailedException e) {
            String providerErrorCode = resolveProviderErrorCode(e);
            if (context != null
                    && isNotifySmsSendingFailureEnabled(context.getTenantDomain())
                    && e.getCause() instanceof IdentityEventException) {
                IdentityEventException cause = (IdentityEventException) e.getCause();
                if (StringUtils.isNotBlank(providerErrorCode)
                        && providerErrorCode.startsWith(SMSOTPConstants.SMS_PROVIDER_ERROR_CODE_PREFIX)) {
                    AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(
                            FrameworkConstants.AuthenticatorMessageType.ERROR,
                            providerErrorCode, cause.getMessage(), null);
                    setAuthenticatorMessage(authenticatorMessage, context);
                    return;
                }
            }
            throw e;
        }
    }

    /**
     * Resolves the error code reported by the SMS provider from a failed notification request.
     *
     * @param e Failure of the SMS OTP notification request.
     * @return Error code reported by the SMS provider, or null when the provider did not report one.
     */
    private String resolveProviderErrorCode(AuthenticationFailedException e) {

        return e.getCause() instanceof IdentityEventException
                ? ((IdentityEventException) e.getCause()).getErrorCode() : null;
    }

    /**
     * Records the SMS OTP notification request sent from the Identity Server to the SMS provider as a diagnostic
     * log. This provides evidence that an SMS OTP was requested from our end for the given user and application,
     * even when the user claims that the SMS was never received.
     *
     * @param resultMessage     Message describing the state of the notification request.
     * @param authenticatedUser Authenticated user for whom the OTP is sent.
     * @param eventProperties   Properties of the SMS notification event.
     * @param providerErrorCode Error code returned by the SMS provider. Can be null.
     * @param resultStatus      Result status of the diagnostic log.
     */
    private void logSmsOtpNotificationRequest(String resultMessage, AuthenticatedUser authenticatedUser,
                                              Map<String, Object> eventProperties, String providerErrorCode,
                                              DiagnosticLog.ResultStatus resultStatus) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                SMSOTPConstants.LogConstants.SMS_OTP_SERVICE,
                SMSOTPConstants.LogConstants.ActionIDs.SEND_SMS_OTP);
        diagnosticLogBuilder
                .resultMessage(resultMessage)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(resultStatus)
                .inputParam(LogConstants.InputKeys.AUTHENTICATOR_NAME, getName());
        if (authenticatedUser != null) {
            /* getLoggableMaskedUserId() applies the masking configuration and falls back to the identifier which
             is available, which getUserName() does not do for a federated user. */
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER,
                    authenticatedUser.getLoggableMaskedUserId());
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.TENANT_DOMAIN,
                    authenticatedUser.getTenantDomain());
        }
        Object serviceProvider = eventProperties != null
                ? eventProperties.get(IdentityEventConstants.EventProperty.APPLICATION_NAME) : null;
        if (serviceProvider != null) {
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.SERVICE_PROVIDER, serviceProvider);
        }
        Object sentTo = eventProperties != null ? eventProperties.get(SMSOTPConstants.ATTRIBUTE_SMS_SENT_TO) : null;
        if (sentTo != null) {
            diagnosticLogBuilder.inputParam(SMSOTPConstants.LogConstants.InputKeys.SEND_TO,
                    LoggerUtils.isLogMaskingEnable
                            ? LoggerUtils.getMaskedContent(String.valueOf(sentTo)) : String.valueOf(sentTo));
        }
        if (StringUtils.isNotBlank(providerErrorCode)) {
            diagnosticLogBuilder.inputParam(SMSOTPConstants.LogConstants.InputKeys.PROVIDER_ERROR_CODE,
                    providerErrorCode);
        }
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }

    @Override
    protected String getOTPPageRedirectErrorCode(AuthenticationContext context) throws AuthenticationFailedException {

        if (isNotifySmsSendingFailureEnabled(context.getTenantDomain())) {
            AuthenticatorMessage authenticatorMessage =
                (AuthenticatorMessage) context.getProperty(SMSOTPConstants.AUTHENTICATOR_MESSAGE);
            if (authenticatorMessage != null
                    && FrameworkConstants.AuthenticatorMessageType.ERROR.equals(authenticatorMessage.getType())
                    && authenticatorMessage.getCode() != null
                    && authenticatorMessage.getCode().startsWith(SMSOTPConstants.SMS_PROVIDER_ERROR_CODE_PREFIX)) {
                return authenticatorMessage.getCode();
            }
        }
        return null;
    }

    @Override
    protected int getMaximumResendAttempts(String tenantDomain) throws AuthenticationFailedException {

        try {
            String allowedResendCount = AuthenticatorUtils.getSmsAuthenticatorConfig(SMSOTPConstants.ConnectorConfig
                    .SMS_OTP_RESEND_ATTEMPTS_COUNT, tenantDomain);
            if (NumberUtils.isNumber(allowedResendCount)) {
                return Integer.parseInt(allowedResendCount);
            }
            return SMSOTPConstants.DEFAULT_OTP_RESEND_ATTEMPTS;
        } catch (SMSOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    @Override
    protected OTPResendClaims getOTPResendClaims() {

        return new OTPResendClaims(SMS_OTP_RESEND_ATTEMPTS_CLAIM, SMS_OTP_LAST_SENT_TIME_CLAIM);
    }

    @Override
    protected int getOTPResendBlockDuration(String tenantDomain) throws AuthenticationFailedException {

        try {
            String allowedResendCount = AuthenticatorUtils.getSmsAuthenticatorConfig(SMSOTPConstants.ConnectorConfig
                    .SMS_OTP_RESEND_BLOCK_DURATION, tenantDomain);
            if (NumberUtils.isNumber(allowedResendCount)) {
                return Integer.parseInt(allowedResendCount);
            }
            return SMSOTPConstants.DEFAULT_OTP_RESEND_BLOCK_DURATION;
        } catch (SMSOTPAuthenticatorServerException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    @Override
    protected boolean isUserBasedOTPResendBlockingEnabled() throws AuthenticationFailedException {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        return Boolean.parseBoolean(parameterMap.get(SMSOTPConstants.SMS_OTP_USER_BASED_RESEND_BLOCKING_ENABLED));
    }

    /**
     * Get the application id from the application name and the tenant domain which application is created on.
     *
     * @param applicationName Application name.
     * @param tenantDomain Tenant domain.
     * @return Application id.
     * @throws AuthenticationFailedException If an error occurred while getting the application id.
     */
    private String getApplicationId(String applicationName, String tenantDomain) throws AuthenticationFailedException {

        try {
            ServiceProvider serviceProvider = AuthenticatorDataHolder.getApplicationManagementService().
                    getServiceProvider(applicationName, tenantDomain);
            return serviceProvider.getApplicationResourceId();
        } catch (IdentityApplicationManagementException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_APPLICATION, e,
                    (Object) null);
        }
    }

    /**
     * Set the authenticator message to the context.
     *
     * @param context AuthenticationContext.
     * @param maskedMobileNumber The masked mobile number.
     */
    private static void setAuthenticatorMessage(AuthenticationContext context, String maskedMobileNumber) {

        String message = "The code is successfully sent to the mobile number: " + maskedMobileNumber;
        Map<String, String> messageContext = new HashMap<>();
        messageContext.put(MASKED_MOBILE_NUMBER, maskedMobileNumber);

        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.INFO, SMS_OTP_SENT, message, messageContext);

        context.setProperty(SMSOTPConstants.AUTHENTICATOR_MESSAGE, authenticatorMessage);
    }

    private boolean doSendMaskedMobileInAppNativeMFA() {

        // If the parameter is not set, default to false.
        String value =
                getAuthenticatorConfig().getParameterMap().get(SMSOTPConstants.SEND_MASKED_MOBILE_IN_APPNATIVE_MFA);
        return Boolean.parseBoolean(value);
    }


    /**
     * Retrieve the claim dialect of the federated authenticator.
     *
     * @param context AuthenticationContext.
     * @return The claim dialect of the federated authenticator.
     */
    private String getFederatedAuthenticatorDialect(AuthenticationContext context) {

        String dialect = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            if (stepConfig.isSubjectAttributeStep()) {
                dialect = stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator().getClaimDialectURI();
                break;
            }
        }
        return dialect;
    }

    /**
     * Get the {@link IdentityProvider} object from the given IDP name and tenant domain.
     * @param idpName IDP name.
     * @param tenantDomain Tenant domain.
     * @return IdentityProvider.
     * @throws AuthenticationFailedException If an error occurred while getting the IdentityProvider.
     */
    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = AuthenticatorDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages
                        .ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages
                    .ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }
    }

    /**
     * Retrieve the mobile number of the federated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Application tenant domain.
     * @param context      AuthenticationContext.
     * @return Mobile number of the federated user.
     * @throws AuthenticationFailedException If an error occurred while getting the mobile number of the federated user.
     */
    private String getMobileNoForFederatedUser(AuthenticatedUser user, String tenantDomain,
                                               AuthenticationContext context) throws AuthenticationFailedException {

        String mobileAttributeKey = resolveMobileNoAttribute(user, tenantDomain, context);
        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        String mobile = null;
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
            if (key.equals(mobileAttributeKey)) {
                String value = entry.getValue();
                mobile = String.valueOf(value);
                break;
            }
        }
        return mobile;
    }

    /**
     * Get the SMS Provider type for the specific tenant.
     * @param tenantDomain Tenant domain.
     * @return SMS Provider type.
     */
    private String getProviderType(String tenantDomain) {

        try {
            Resource resource = AuthenticatorDataHolder.getConfigurationManager().getResource(SMSOTPConstants.PUBLISHER,
                    SMSOTPConstants.SMS_PROVIDER);
            if (resource != null) {
                return SMSOTPConstants.ProviderTypes.CUSTOM;
            }
        } catch (ConfigurationManagementException e) {
            if (e.getErrorCode()
                    .equals(ERROR_CODE_FEATURE_NOT_ENABLED.getCode())) {
                LOG.warn("Configuration store is disabled. Super tenant configurations are using for the tenant "
                        + "domain: " + tenantDomain);
            } else if (e.getErrorCode()
                    .equals(ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode())) {
                LOG.warn("Configuration store does not contain resource SMSPublisher. Super "
                        + "tenant configurations are using for the tenant domain: " + tenantDomain);
            } else if (e.getErrorCode()
                    .equals(ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode())) {
                LOG.warn("Configuration store does not contain  publisher resource type. Super "
                        + "tenant configurations are using for the tenant domain: " + tenantDomain);
            } else {
                LOG.error("Error occurred while fetching the tenant specific publisher configuration files " +
                        "from configuration store for the tenant domain: " + tenantDomain, e);
            }
        }
        return SMSOTPConstants.ProviderTypes.DEFAULT;
    }

    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws AuthenticationFailedException If an error occurred while getting the UserRealm.
     */
    private UserRealm getTenantUserRealm(String tenantDomain) throws AuthenticationFailedException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (AuthenticatorDataHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM, e,
                    tenantDomain);
        }
        if (userRealm == null) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM,
                    tenantDomain);
        }
        return userRealm;
    }

    /**
     * Get user claim value.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(AuthenticatedUser authenticatedUser , AuthenticationContext context)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()),
                            new String[]{SMSOTPConstants.Claims.MOBILE_CLAIM}, null);
            return claimValues.get(SMSOTPConstants.Claims.MOBILE_CLAIM);
        } catch (UserStoreException e) {
            AuthenticatorMessage authenticatorMessage =
                    new AuthenticatorMessage(FrameworkConstants.AuthenticatorMessageType.ERROR,
                            AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_MOBILE_NUMBER.getCode(),
                            AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_MOBILE_NUMBER.getMessage(),
                            null);
            setAuthenticatorMessage(authenticatorMessage, context);
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_MOBILE_NUMBER,
                    e, authenticatedUser.getUserName());
        }
    }

    private static void setAuthenticatorMessage(AuthenticatorMessage errorMessage, AuthenticationContext context) {

        context.setProperty(SMSOTPConstants.AUTHENTICATOR_MESSAGE, errorMessage);
    }


    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw handleAuthErrorScenario(
                        AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER,
                        username);
            }
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, e,
                    username);
        }
    }

    /**
     * Resolve the mobile number attribute for the federated user by evaluating the federated IDP.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Application tenant domain.
     * @param context      AuthenticationContext.
     * @return mobile number attribute.
     * @throws AuthenticationFailedException If an error occurred while resolving mobile number attribute.
     */
    private String resolveMobileNoAttribute(AuthenticatedUser user, String tenantDomain,
                                            AuthenticationContext context) throws AuthenticationFailedException {

        // Prioritizing the authenticator's dialect first, then considering the claim mapping defined in the IdP.
        String dialect = getFederatedAuthenticatorDialect(context);
        if (SMSOTPConstants.OIDC_DIALECT_URI.equals(dialect)) {
            return SMSOTPConstants.MOBILE_ATTRIBUTE_KEY;
        }
        if (SMSOTPConstants.WSO2_CLAIM_DIALECT.equals(dialect)) {
            return SMSOTPConstants.Claims.MOBILE_CLAIM;
        }
        // If the dialect is not OIDC we need to check claim mappings for the mobile claim mapped attribute.
        String idpName = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(idpName, tenantDomain);
        ClaimConfig claimConfigs = idp.getClaimConfig();
        if (claimConfigs == null) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages
                    .ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }
        ClaimMapping[] claimMappings = claimConfigs.getClaimMappings();
        if (ArrayUtils.isEmpty(claimMappings)) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages
                            .ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR, idpName, tenantDomain);
        }

        String mobileAttributeKey = null;
        for (ClaimMapping claimMapping : claimMappings) {
            if (SMSOTPConstants.Claims.MOBILE_CLAIM.equals(claimMapping.getLocalClaim().getClaimUri())) {
                mobileAttributeKey = claimMapping.getRemoteClaim().getClaimUri();
                break;
            }
        }
        if (StringUtils.isBlank(mobileAttributeKey)) {
            AuthenticatorMessage authenticatorMessage =
                    new AuthenticatorMessage(FrameworkConstants.AuthenticatorMessageType.ERROR,
                            AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_MOBILE_CLAIM_MAPPINGS.getCode(),
                            AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_MOBILE_CLAIM_MAPPINGS.getMessage(),
                            null);
            setAuthenticatorMessage(authenticatorMessage, context);
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_MOBILE_CLAIM_MAPPINGS,
                    idpName, tenantDomain);
        }
        return mobileAttributeKey;
    }

    /**
     * Resolve the mobile number of the authenticated user.
     *
     * @param user                       Authenticated user.
     * @param tenantDomain               Application tenant domain.
     * @param context                    AuthenticationContext.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return Mobile number of the authenticated user.
     * @throws AuthenticationFailedException If an error occurred while resolving the mobile number.
     */
    private String resolveMobileNoOfAuthenticatedUser(AuthenticatedUser user, String tenantDomain,
                                                      AuthenticationContext context, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        String mobile;
        if (isInitialFederationAttempt) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Getting the mobile number of the initially federating user: %s",
                        user.getUserName()));
            }
            mobile = getMobileNoForFederatedUser(user, tenantDomain, context);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Getting the mobile number of the local user: %s in user store: %s in " +
                        "tenant: %s", user.getUserName(), user.getUserStoreDomain(), user.getTenantDomain()));
            }
            mobile = getUserClaimValueFromUserStore(user, context);
            if (StringUtils.isBlank(mobile)) {
                /* A user who does not have a mobile number may be enrolling one. The OTP is then sent to the number
                 pending enrollment, which is saved to the profile only after the OTP is verified. */
                mobile = getPendingMobileNumber(context);
            }
        }
        return mobile;
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        String idpName = null;

        AuthenticatedUser authenticatedUser = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
            authenticatedUser = context.getLastAuthenticatedUser();
        }

        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(SMSOTPConstants.AUTHENTICATOR_SMS_OTP);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        List<String> requiredParams = new ArrayList<>();
        if (context != null && isAwaitingMobileNumber(context)) {
            AuthenticatorParamMetadata mobileNumberMetadata = new AuthenticatorParamMetadata(
                    SMSOTPConstants.MOBILE_NUMBER, SMSOTPConstants.MobileNumberEnrollment.DISPLAY_MOBILE_NUMBER,
                    FrameworkConstants.AuthenticatorParamType.STRING, 0, Boolean.FALSE,
                    SMSOTPConstants.MobileNumberEnrollment.MOBILE_NUMBER_PARAM_KEY);
            authenticatorParamMetadataList.add(mobileNumberMetadata);
            requiredParams.add(SMSOTPConstants.MOBILE_NUMBER);
        } else if (authenticatedUser == null) {
            AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                    USERNAME, DISPLAY_USERNAME, FrameworkConstants.AuthenticatorParamType.STRING,
                    0, Boolean.FALSE, SMSOTPConstants.USERNAME_PARAM_KEY);
            authenticatorParamMetadataList.add(usernameMetadata);
            requiredParams.add(USERNAME);
        } else {
            AuthenticatorParamMetadata codeMetadata = new AuthenticatorParamMetadata(
                    CODE, DISPLAY_CODE, FrameworkConstants.AuthenticatorParamType.STRING,
                    1, Boolean.TRUE, SMSOTPConstants.CODE_PARAM);
            authenticatorParamMetadataList.add(codeMetadata);
            requiredParams.add(CODE);
        }

        // If the configuration is enabled, and if it is a MFA Option, IS will send the masked mobile number.
        if (context != null && context.getProperty(SMSOTPConstants.AUTHENTICATOR_MESSAGE) != null && doSendMaskedMobileInAppNativeMFA()
                && !isOTPAsFirstFactor(context)) {
            authenticatorData.setMessage((AuthenticatorMessage) context.getProperty(SMSOTPConstants.AUTHENTICATOR_MESSAGE));
        }
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        authenticatorData.setRequiredParams(requiredParams);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
        return Optional.of(authenticatorData);
    }

    @Override
    protected boolean useOnlyNumericChars(String tenantDomain) throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(AuthenticatorUtils.getSmsAuthenticatorConfig
                    (SMSOTPConstants.ConnectorConfig.SMS_OTP_USE_NUMERIC_CHARS, tenantDomain));
        } catch (SMSOTPAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG);
        }
    }

    @Override
    protected String getCaptchaParams(HttpServletRequest request, AuthenticationContext context, String tenantDomain,
                                      AuthenticatedUser authenticatedUser) {

        String captchaParams = StringUtils.EMPTY;
        AbstractOTPCaptchaConnector smsOTPCaptchaConnector = new LocalSMSOTPCaptchaConnector();
        smsOTPCaptchaConnector.init(AuthenticatorDataHolder.getIdentityGovernanceService());
        try {
            if (smsOTPCaptchaConnector.isRecaptchaEnabled(request) && isOTPAsFirstFactor(context)) {
                captchaParams = "&reCaptcha=true";
            }
        } catch (CaptchaException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to determine if recaptcha for SMS OTP is enabled", e);
            }
        }

        return captchaParams;
    }

    @Override
    protected void redirectToOTPLoginPage(AuthenticatedUser authenticatedUser, String tenantDomain,
                                          boolean isInitialFederationAttempt, HttpServletResponse response,
                                          HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        super.redirectToOTPLoginPage(authenticatedUser, tenantDomain, isInitialFederationAttempt, response,
                request, context);
        context.setProperty(SMSOTPConstants.IS_REDIRECT_TO_SMS_OTP, "true");
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (handleMobileNumberEnrollment(request, response, context)) {
            return;
        }
        super.initiateAuthenticationRequest(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        context.removeProperty(SMSOTPConstants.IS_REDIRECT_TO_SMS_OTP);
        super.processAuthenticationResponse(request, response, context);
        // Reaching here means the OTP sent to the mobile number pending enrollment, if any, is verified.
        completeMobileNumberEnrollment(context);
    }

    @Override
    protected String getResendAttemptsPropertyKey() {

        return SMS_OTP_RESEND_ATTEMPTS_PROPERTY_NAME;
    }

    @Override
    protected String getRetryAttemptsPropertyKey() {

        return SMS_OTP_RETRY_ATTEMPTS_PROPERTY_NAME;
    }

    /**
     * Handle enrolling a mobile number for a user who does not have one configured, when mobile number enrollment is
     * enabled. The user is requested to enter a mobile number, an OTP is sent to that number, and the number is saved
     * to the user profile only after the OTP is verified.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @return True if the request is handled by redirecting the user, false if the OTP flow should continue.
     * @throws AuthenticationFailedException If an error occurred while handling the enrollment.
     */
    protected boolean handleMobileNumberEnrollment(HttpServletRequest request, HttpServletResponse response,
                                                   AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser user = resolveUserEligibleForMobileNumberEnrollment(context);
        if (user == null) {
            clearMobileNumberEnrollment(context);
            return false;
        }
        if (isMobileNumberSubmission(request, context)) {
            return handleSubmittedMobileNumber(request, response, context, user);
        }
        if (StringUtils.isNotBlank(getPendingMobileNumber(context))) {
            // An OTP is sent to the number pending enrollment. Resending and verifying it continue as usual.
            return false;
        }
        String errorQueryParams = (String) context.getProperty(
                SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ERROR);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ERROR);
        redirectToMobileNumberRequestPage(request, response, context, errorQueryParams);
        return true;
    }

    /**
     * Resolve the user, if the user is eligible to enroll a mobile number in the current authentication flow.
     *
     * @param context AuthenticationContext.
     * @return The user if eligible to enroll a mobile number, null otherwise.
     * @throws AuthenticationFailedException If an error occurred while resolving the user.
     */
    private AuthenticatedUser resolveUserEligibleForMobileNumberEnrollment(AuthenticationContext context)
            throws AuthenticationFailedException {

        // A mobile number is enrolled only for a user who is identified by a preceding authentication step.
        if (isOTPAsFirstFactor(context) || !isMobileNumberEnrollmentEnabled(context)) {
            return null;
        }
        AuthenticatedUser user = getSubjectAuthenticatedUser(context);
        // Attributes of federated users are managed by the federated identity provider.
        if (user == null || user.isFederatedUser()) {
            return null;
        }
        // A mobile number configured for the user is never replaced from the authentication flow.
        if (StringUtils.isNotBlank(getUserClaimValueFromUserStore(user, context))) {
            return null;
        }
        if (AuthenticatorUtils.isAccountLocked(user)) {
            return null;
        }
        return user;
    }

    /**
     * Check whether mobile number enrollment is enabled. An application can opt out from the authentication script,
     * but cannot enable the enrollment when it is not enabled for the organization.
     *
     * @param context AuthenticationContext.
     * @return True if mobile number enrollment is enabled.
     * @throws AuthenticationFailedException If an error occurred while getting the configuration.
     */
    private boolean isMobileNumberEnrollmentEnabled(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (MapUtils.isNotEmpty(runtimeParams)) {
            String enrolUser = runtimeParams.get(
                    SMSOTPConstants.MobileNumberEnrollment.ENROL_USER_IN_AUTHENTICATION_FLOW);
            if (StringUtils.isNotBlank(enrolUser) && !Boolean.parseBoolean(enrolUser)) {
                return false;
            }
        }
        try {
            return Boolean.parseBoolean(AuthenticatorUtils.getSmsAuthenticatorConfig(
                    SMSOTPConstants.ConnectorConfig.SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW,
                    context.getTenantDomain()));
        } catch (SMSOTPAuthenticatorServerException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG, e);
        }
    }

    /**
     * Check whether the request submits a mobile number for enrollment, while a mobile number is requested from the
     * user or is pending enrollment.
     *
     * @param request HttpServletRequest.
     * @param context AuthenticationContext.
     * @return True if a mobile number is submitted for enrollment.
     */
    private boolean isMobileNumberSubmission(HttpServletRequest request, AuthenticationContext context) {

        return SMS_OTP_AUTHENTICATOR_NAME.equals(context.getCurrentAuthenticator())
                && StringUtils.isNotBlank(request.getParameter(SMSOTPConstants.MOBILE_NUMBER))
                && StringUtils.isBlank(request.getParameter(CODE))
                && !Boolean.parseBoolean(request.getParameter(RESEND))
                && (isAwaitingMobileNumber(context) || StringUtils.isNotBlank(getPendingMobileNumber(context)));
    }

    /**
     * Handle a mobile number submitted for enrollment. A valid number is kept as pending enrollment, so that the OTP
     * is sent to it. A number is never saved to the user profile from here.
     *
     * @param request  HttpServletRequest.
     * @param response HttpServletResponse.
     * @param context  AuthenticationContext.
     * @param user     User who enrolls the mobile number.
     * @return True if the request is handled by redirecting the user, false if an OTP should be sent to the number.
     * @throws AuthenticationFailedException If an error occurred while handling the mobile number.
     */
    private boolean handleSubmittedMobileNumber(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationContext context, AuthenticatedUser user)
            throws AuthenticationFailedException {

        String mobileNumber = normalizeMobileNumber(request.getParameter(SMSOTPConstants.MOBILE_NUMBER));
        if (!isValidMobileNumber(mobileNumber, context.getTenantDomain())) {
            logMobileNumberEnrollment("The mobile number submitted for enrollment is not valid.", user, null,
                    DiagnosticLog.ResultStatus.FAILED);
            redirectToMobileNumberRequestPage(request, response, context,
                    SMSOTPConstants.MobileNumberEnrollment.ERROR_MOBILE_NUMBER_INVALID_QUERY_PARAMS);
            return true;
        }
        if (!mobileNumber.equals(getPendingMobileNumber(context))) {
            int enrollmentAttempts = getMobileNumberEnrollmentAttempts(context);
            if (enrollmentAttempts >= getMaximumMobileNumberEnrollmentAttempts()) {
                logMobileNumberEnrollment("The maximum number of mobile numbers allowed to be submitted for " +
                        "enrollment is exceeded.", user, null, DiagnosticLog.ResultStatus.FAILED);
                invalidateOTP(context);
                context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.AWAITING_MOBILE_NUMBER);
                context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.PENDING_MOBILE_NUMBER);
                redirectToEnrollmentErrorPage(request, response, context,
                        SMSOTPConstants.MobileNumberEnrollment.ERROR_ENROLLMENT_ATTEMPTS_EXCEEDED_QUERY_PARAMS);
                return true;
            }
            context.setProperty(SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ATTEMPTS, enrollmentAttempts + 1);
            context.setProperty(SMSOTPConstants.MobileNumberEnrollment.PENDING_MOBILE_NUMBER, mobileNumber);
            /* Invalidates an OTP sent to an earlier number. Otherwise, it could verify the new number if sending an
             OTP to the new number is not allowed, such as when the resend limit is exceeded. */
            invalidateOTP(context);
        }
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.AWAITING_MOBILE_NUMBER);
        // An OTP is sent to the submitted number afresh. Hence, failures of an earlier OTP are not carried forward.
        context.setRetrying(false);
        logMobileNumberEnrollment("Sending an OTP to verify the mobile number submitted for enrollment.", user,
                mobileNumber, DiagnosticLog.ResultStatus.SUCCESS);
        return false;
    }

    /**
     * Save the mobile number pending enrollment to the user profile, once the OTP sent to it is verified.
     *
     * @param context AuthenticationContext.
     * @throws AuthenticationFailedException If the mobile number could not be saved.
     */
    protected void completeMobileNumberEnrollment(AuthenticationContext context)
            throws AuthenticationFailedException {

        String mobileNumber = getPendingMobileNumber(context);
        if (StringUtils.isBlank(mobileNumber)) {
            return;
        }
        Object otpSentToMobileNumber = context.getProperty(
                SMSOTPConstants.MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER);
        // The verified OTP is consumed. Hence, the number cannot be saved through another attempt with the same OTP.
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.PENDING_MOBILE_NUMBER);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.AWAITING_MOBILE_NUMBER);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER);

        AuthenticatedUser user = getSubjectAuthenticatedUser(context);
        if (user == null || user.isFederatedUser()) {
            clearMobileNumberEnrollment(context);
            return;
        }
        if (!mobileNumber.equals(otpSentToMobileNumber)) {
            // Possession of the number is proven only by an OTP sent to that number.
            context.setProperty(SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ERROR,
                    SMSOTPConstants.MobileNumberEnrollment.ERROR_ENROLLMENT_FAILED_QUERY_PARAMS);
            logMobileNumberEnrollment("The mobile number is not enrolled since the verified OTP was not sent to " +
                    "that number.", user, null, DiagnosticLog.ResultStatus.FAILED);
            throw new AuthenticationFailedException(
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_MOBILE_NUMBER.getCode(),
                    String.format(SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_MOBILE_NUMBER.getMessage(),
                            user.getLoggableMaskedUserId()));
        }
        String existingMobileNumber = getUserClaimValueFromUserStore(user, context);
        if (StringUtils.isNotBlank(existingMobileNumber)) {
            if (existingMobileNumber.equals(mobileNumber)) {
                clearMobileNumberEnrollment(context);
                return;
            }
            // A mobile number configured while the enrollment was in progress is never replaced.
            logMobileNumberEnrollment("The mobile number is not enrolled since another mobile number was configured " +
                    "for the user while the enrollment was in progress.", user, null,
                    DiagnosticLog.ResultStatus.FAILED);
            throw new AuthenticationFailedException(
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_MOBILE_NUMBER_ALREADY_CONFIGURED.getCode(),
                    String.format(SMSOTPConstants.ErrorMessages.ERROR_CODE_MOBILE_NUMBER_ALREADY_CONFIGURED.getMessage(),
                            user.getLoggableMaskedUserId()));
        }

        Map<String, String> claims = new HashMap<>();
        claims.put(SMSOTPConstants.Claims.MOBILE_CLAIM, mobileNumber);
        // The number is verified by the OTP sent to it.
        claims.put(SMSOTPConstants.Claims.MOBILE_VERIFIED_CLAIM, Boolean.TRUE.toString());
        UserStoreManager userStoreManager = getUserStoreManager(user);
        try {
            /* Mobile number updates initiate a verification of the new number when mobile number verification is
             enabled. That is skipped since the number is already verified. */
            Utils.setThreadLocalToSkipSendingSmsOtpVerificationOnUpdate(IdentityRecoveryConstants
                    .SkipMobileNumberVerificationOnUpdateStates.SKIP_ON_SMS_OTP_FLOW.toString());
            userStoreManager.setUserClaimValues(
                    MultitenantUtils.getTenantAwareUsername(user.toFullQualifiedUsername()), claims, null);
        } catch (UserStoreException e) {
            // The reason is not sent to the user, since it is not guaranteed to be free of internal details.
            context.setProperty(SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ERROR,
                    SMSOTPConstants.MobileNumberEnrollment.ERROR_ENROLLMENT_FAILED_QUERY_PARAMS);
            logMobileNumberEnrollment("Failed to save the verified mobile number to the user profile.", user, null,
                    DiagnosticLog.ResultStatus.FAILED);
            throw new AuthenticationFailedException(
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_MOBILE_NUMBER.getCode(),
                    String.format(SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_ENROLLING_MOBILE_NUMBER.getMessage(),
                            user.getLoggableMaskedUserId()), e);
        } finally {
            Utils.unsetThreadLocalToSkipSendingSmsOtpVerificationOnUpdate();
        }
        clearMobileNumberEnrollment(context);
        logMobileNumberEnrollment("The mobile number is enrolled successfully.", user, mobileNumber,
                DiagnosticLog.ResultStatus.SUCCESS);
    }

    /**
     * Redirect the user to the page which requests a mobile number.
     *
     * @param request          HttpServletRequest.
     * @param response         HttpServletResponse.
     * @param context          AuthenticationContext.
     * @param errorQueryParams Query params of the error to be shown on the page. Can be null.
     * @throws AuthenticationFailedException If an error occurred while redirecting.
     */
    private void redirectToMobileNumberRequestPage(HttpServletRequest request, HttpServletResponse response,
                                                   AuthenticationContext context, String errorQueryParams)
            throws AuthenticationFailedException {

        StringBuilder queryParams = new StringBuilder(FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier()))
                .append(SMSOTPConstants.AUTHENTICATORS_QUERY_PARAM).append(getName())
                .append(AuthenticatorUtils.getMultiOptionURIQueryParam(request));
        if (StringUtils.isNotBlank(errorQueryParams)) {
            queryParams.append(errorQueryParams);
        }
        context.setProperty(SMSOTPConstants.MobileNumberEnrollment.AWAITING_MOBILE_NUMBER, true);
        try {
            String mobileNumberRequestPage = AuthenticatorUtils.getMobileNumberRequestPageUrl(
                    getAuthenticatorParameter(
                            SMSOTPConstants.MobileNumberEnrollment.MOBILE_NUMBER_REQUEST_PAGE_URL_CONFIG));
            response.sendRedirect(FrameworkUtils.appendQueryParamsStringToUrl(mobileNumberRequestPage,
                    queryParams.toString()));
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_REDIRECTING_TO_MOBILE_NUMBER_REQUEST_PAGE.getCode(),
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_REDIRECTING_TO_MOBILE_NUMBER_REQUEST_PAGE.getMessage(), e);
        }
    }

    /**
     * Redirect the user to the error page, when the mobile number enrollment cannot be continued.
     *
     * @param request          HttpServletRequest.
     * @param response         HttpServletResponse.
     * @param context          AuthenticationContext.
     * @param errorQueryParams Query params of the error to be shown on the page.
     * @throws AuthenticationFailedException If an error occurred while redirecting.
     */
    private void redirectToEnrollmentErrorPage(HttpServletRequest request, HttpServletResponse response,
                                               AuthenticationContext context, String errorQueryParams)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())
                + SMSOTPConstants.AUTHENTICATORS_QUERY_PARAM + getName() + errorQueryParams
                + AuthenticatorUtils.getMultiOptionURIQueryParam(request);
        try {
            response.sendRedirect(FrameworkUtils.appendQueryParamsStringToUrl(getErrorPageURL(context), queryParams));
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE.getCode(),
                    SMSOTPConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE.getMessage(), e);
        }
    }

    /**
     * Remove whitespaces and hyphens, which are commonly used to format mobile numbers.
     *
     * @param mobileNumber Mobile number submitted by the user.
     * @return Mobile number without formatting characters, or null if blank.
     */
    private static String normalizeMobileNumber(String mobileNumber) {

        if (StringUtils.isBlank(mobileNumber)) {
            return null;
        }
        return mobileNumber.replaceAll("[\\s-]", StringUtils.EMPTY);
    }

    /**
     * Validate a mobile number submitted for enrollment against the regex configured for the organization, or the
     * default regex when none is configured.
     *
     * @param mobileNumber Normalized mobile number.
     * @param tenantDomain Tenant domain.
     * @return True if the mobile number is valid.
     * @throws AuthenticationFailedException If an error occurred while getting the configuration.
     */
    private boolean isValidMobileNumber(String mobileNumber, String tenantDomain)
            throws AuthenticationFailedException {

        if (StringUtils.isBlank(mobileNumber)
                || mobileNumber.length() > SMSOTPConstants.MobileNumberEnrollment.MAX_MOBILE_NUMBER_LENGTH) {
            return false;
        }
        String mobileNumberRegex;
        try {
            mobileNumberRegex = AuthenticatorUtils.getSmsAuthenticatorConfig(
                    SMSOTPConstants.ConnectorConfig.SMS_OTP_MOBILE_NUMBER_REGEX, tenantDomain);
        } catch (SMSOTPAuthenticatorServerException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG, e);
        }
        if (StringUtils.isBlank(mobileNumberRegex)) {
            mobileNumberRegex = SMSOTPConstants.MobileNumberEnrollment.DEFAULT_MOBILE_NUMBER_REGEX;
        }
        try {
            return Pattern.matches(mobileNumberRegex, mobileNumber);
        } catch (PatternSyntaxException e) {
            // No number is accepted, so that a restriction intended by the configured regex is never bypassed.
            LOG.error(String.format("The mobile number regex configured for SMS OTP in tenant: %s is not valid. " +
                    "Hence, mobile numbers cannot be enrolled.", tenantDomain), e);
            return false;
        }
    }

    /**
     * Get the maximum number of different mobile numbers that a user can submit for enrollment in a flow.
     *
     * @return Maximum number of mobile numbers.
     */
    private int getMaximumMobileNumberEnrollmentAttempts() {

        String maxAttempts = getAuthenticatorParameter(
                SMSOTPConstants.MobileNumberEnrollment.MAX_ENROLLMENT_ATTEMPTS_CONFIG);
        if (NumberUtils.isDigits(maxAttempts) && Integer.parseInt(maxAttempts) > 0) {
            return Integer.parseInt(maxAttempts);
        }
        return SMSOTPConstants.MobileNumberEnrollment.DEFAULT_MAX_ENROLLMENT_ATTEMPTS;
    }

    private String getAuthenticatorParameter(String parameterName) {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        return MapUtils.isNotEmpty(parameterMap) ? parameterMap.get(parameterName) : null;
    }

    private static boolean isAwaitingMobileNumber(AuthenticationContext context) {

        return Boolean.TRUE.equals(context.getProperty(SMSOTPConstants.MobileNumberEnrollment.AWAITING_MOBILE_NUMBER));
    }

    private static String getPendingMobileNumber(AuthenticationContext context) {

        Object mobileNumber = context.getProperty(SMSOTPConstants.MobileNumberEnrollment.PENDING_MOBILE_NUMBER);
        return mobileNumber instanceof String ? (String) mobileNumber : null;
    }

    private static int getMobileNumberEnrollmentAttempts(AuthenticationContext context) {

        Object attempts = context.getProperty(SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ATTEMPTS);
        return attempts instanceof Integer ? (Integer) attempts : 0;
    }

    private static void invalidateOTP(AuthenticationContext context) {

        context.removeProperty(AuthenticatorConstants.OTP);
        context.removeProperty(SMSOTPConstants.OTP_TOKEN);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER);
    }

    private static void clearMobileNumberEnrollment(AuthenticationContext context) {

        if (context.getProperty(SMSOTPConstants.MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER) != null) {
            /* An OTP sent to a number pending enrollment must not complete the authentication once the enrollment
             is discontinued, such as when a mobile number is configured for the user in the meantime. */
            invalidateOTP(context);
        }
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.AWAITING_MOBILE_NUMBER);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.PENDING_MOBILE_NUMBER);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.OTP_SENT_TO_MOBILE_NUMBER);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ATTEMPTS);
        context.removeProperty(SMSOTPConstants.MobileNumberEnrollment.ENROLLMENT_ERROR);
    }

    /**
     * Get the user identified by the subject attribute step of the authentication flow.
     *
     * @param context AuthenticationContext.
     * @return The user, or null if no user is identified yet.
     */
    private static AuthenticatedUser getSubjectAuthenticatedUser(AuthenticationContext context) {

        if (context.getSequenceConfig() == null || context.getSequenceConfig().getStepMap() == null) {
            return null;
        }
        for (StepConfig stepConfig : context.getSequenceConfig().getStepMap().values()) {
            if (stepConfig.isSubjectAttributeStep() && stepConfig.getAuthenticatedUser() != null) {
                return new AuthenticatedUser(stepConfig.getAuthenticatedUser());
            }
        }
        return null;
    }

    /**
     * Record the progress of a mobile number enrollment as a diagnostic log.
     *
     * @param resultMessage Message describing the progress.
     * @param user          User who enrolls the mobile number.
     * @param mobileNumber  Mobile number related to the progress. Can be null.
     * @param resultStatus  Result status of the diagnostic log.
     */
    private void logMobileNumberEnrollment(String resultMessage, AuthenticatedUser user, String mobileNumber,
                                           DiagnosticLog.ResultStatus resultStatus) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                SMSOTPConstants.LogConstants.SMS_OTP_SERVICE,
                SMSOTPConstants.LogConstants.ActionIDs.ENROLL_MOBILE_NUMBER);
        diagnosticLogBuilder
                .resultMessage(resultMessage)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(resultStatus)
                .inputParam(LogConstants.InputKeys.AUTHENTICATOR_NAME, getName());
        if (user != null) {
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER, user.getLoggableMaskedUserId());
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.TENANT_DOMAIN, user.getTenantDomain());
        }
        if (StringUtils.isNotBlank(mobileNumber)) {
            diagnosticLogBuilder.inputParam(SMSOTPConstants.LogConstants.InputKeys.SEND_TO,
                    LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(mobileNumber) : mobileNumber);
        }
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }
}
