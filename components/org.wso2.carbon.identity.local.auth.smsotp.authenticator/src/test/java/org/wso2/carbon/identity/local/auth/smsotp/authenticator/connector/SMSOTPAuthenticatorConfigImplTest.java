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

package org.wso2.carbon.identity.local.auth.smsotp.authenticator.connector;

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW;
import static org.wso2.carbon.identity.local.auth.smsotp.authenticator.constant.SMSOTPConstants.ConnectorConfig.SMS_OTP_MOBILE_NUMBER_REGEX;

public class SMSOTPAuthenticatorConfigImplTest {

    @Test
    public void testMobileNumberEnrollmentPropertiesAreExposed() {

        SMSOTPAuthenticatorConfigImpl config = new SMSOTPAuthenticatorConfigImpl();
        List<String> propertyNames = Arrays.asList(config.getPropertyNames());

        assertTrue(propertyNames.contains(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW));
        assertTrue(propertyNames.contains(SMS_OTP_MOBILE_NUMBER_REGEX));
        assertTrue(config.getPropertyNameMapping().containsKey(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW));
        assertTrue(config.getPropertyNameMapping().containsKey(SMS_OTP_MOBILE_NUMBER_REGEX));
        assertTrue(config.getPropertyDescriptionMapping().containsKey(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW));
        assertTrue(config.getPropertyDescriptionMapping().containsKey(SMS_OTP_MOBILE_NUMBER_REGEX));
    }

    @Test
    public void testMobileNumberEnrollmentIsDisabledByDefault() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn(null);

            Properties defaults = new SMSOTPAuthenticatorConfigImpl().getDefaultPropertyValues("carbon.super");

            assertEquals(defaults.getProperty(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW), "false");
            assertEquals(defaults.getProperty(SMS_OTP_MOBILE_NUMBER_REGEX), "");
        }
    }

    @Test
    public void testMobileNumberEnrollmentDefaultsCanBeOverridden() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn(null);
            identityUtil.when(() -> IdentityUtil.getProperty(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW))
                    .thenReturn("true");
            identityUtil.when(() -> IdentityUtil.getProperty(SMS_OTP_MOBILE_NUMBER_REGEX))
                    .thenReturn("^\\+94[0-9]{9}$");

            Properties defaults = new SMSOTPAuthenticatorConfigImpl().getDefaultPropertyValues("carbon.super");

            assertEquals(defaults.getProperty(SMS_OTP_ENROL_USER_IN_AUTHENTICATION_FLOW), "true");
            assertEquals(defaults.getProperty(SMS_OTP_MOBILE_NUMBER_REGEX), "^\\+94[0-9]{9}$");
        }
    }

    @Test
    public void testGetName() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetFriendlyName() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetCategory() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetSubCategory() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetOrder() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetPropertyNameMapping() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetPropertyDescriptionMapping() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetPropertyNames() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testGetDefaultPropertyValues() {
        assertTrue(true, "Test case not implemented yet");
    }

    @Test
    public void testTestGetDefaultPropertyValues() {
        assertTrue(true, "Test case not implemented yet");
    }
}
