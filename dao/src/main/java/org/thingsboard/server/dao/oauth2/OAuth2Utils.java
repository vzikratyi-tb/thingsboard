/**
 * Copyright © 2016-2020 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.dao.oauth2;

import org.springframework.util.StringUtils;
import org.thingsboard.server.common.data.oauth2.OAuth2ClientInfo;
import org.thingsboard.server.common.data.oauth2.OAuth2ClientRegistration;
import org.thingsboard.server.common.data.oauth2.OAuth2ClientsParams;

import java.util.stream.Stream;

public class OAuth2Utils {
    public static final String OAUTH2_CLIENT_REGISTRATIONS_PARAMS = "oauth2ClientRegistrationsParams";
    public static final String OAUTH2_CLIENT_REGISTRATIONS_DOMAIN_NAME_PREFIX = "oauth2ClientRegistrationsDomainNamePrefix";
    public static final String ALLOW_OAUTH2_CONFIGURATION = "allowOAuth2Configuration";
    public static final String SYSTEM_SETTINGS_OAUTH2_VALUE = "value";
    public static final String OAUTH2_AUTHORIZATION_PATH_TEMPLATE = "/oauth2/authorization/%s";

    public static String constructAdminSettingsDomainKey(String domainName) {
        String clientRegistrationsKey;
        if (StringUtils.isEmpty(domainName)) {
            clientRegistrationsKey = OAUTH2_CLIENT_REGISTRATIONS_PARAMS;
        } else {
            clientRegistrationsKey = OAUTH2_CLIENT_REGISTRATIONS_DOMAIN_NAME_PREFIX + "_" + domainName;
        }
        return clientRegistrationsKey;
    }

    public static OAuth2ClientInfo toClientInfo(OAuth2ClientRegistration clientRegistration) {
        OAuth2ClientInfo client = new OAuth2ClientInfo();
        client.setName(clientRegistration.getLoginButtonLabel());
        client.setUrl(String.format(OAUTH2_AUTHORIZATION_PATH_TEMPLATE, clientRegistration.getRegistrationId()));
        client.setIcon(clientRegistration.getLoginButtonIcon());
        return client;
    }

    public static Stream<OAuth2ClientRegistration> toClientRegistrationStream(OAuth2ClientsParams oAuth2ClientsParams) {
        return oAuth2ClientsParams.getClientsDomainsParams().stream()
                .flatMap(oAuth2ClientsDomainParams -> oAuth2ClientsDomainParams.getClientRegistrations().stream());
    }
}
