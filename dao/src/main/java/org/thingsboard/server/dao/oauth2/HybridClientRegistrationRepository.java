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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import org.thingsboard.server.common.data.oauth2.OAuth2ClientRegistration;

@Component
public class HybridClientRegistrationRepository implements ClientRegistrationRepository {

    @Autowired
    private OAuth2Service oAuth2Service;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        OAuth2ClientRegistration localClientRegistration = oAuth2Service.getClientRegistration(registrationId);
        return localClientRegistration == null ?
                null : toSpringClientRegistration(localClientRegistration);
    }

    private ClientRegistration toSpringClientRegistration(OAuth2ClientRegistration localClientRegistration){
        return ClientRegistration.withRegistrationId(localClientRegistration.getRegistrationId())
                .clientId(localClientRegistration.getClientId())
                .authorizationUri(localClientRegistration.getAuthorizationUri())
                .clientSecret(localClientRegistration.getClientSecret())
                .tokenUri(localClientRegistration.getTokenUri())
                .redirectUriTemplate(localClientRegistration.getRedirectUriTemplate())
                .scope(localClientRegistration.getScope().split(","))
                .clientName(localClientRegistration.getClientName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .userInfoUri(localClientRegistration.getUserInfoUri())
                .userNameAttributeName(localClientRegistration.getUserNameAttributeName())
                .jwkSetUri(localClientRegistration.getJwkSetUri())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(localClientRegistration.getClientAuthenticationMethod()))
                .build();
    }
}
