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

import org.thingsboard.server.common.data.oauth2.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class OAuth2Utils {
    public static final String OAUTH2_AUTHORIZATION_PATH_TEMPLATE = "/oauth2/authorization/%s";

    public static OAuth2ClientInfo toClientInfo(OAuth2ClientRegistrationInfo clientRegistration) {
        OAuth2ClientInfo client = new OAuth2ClientInfo();
        client.setName(clientRegistration.getLoginButtonLabel());
        client.setUrl(String.format(OAUTH2_AUTHORIZATION_PATH_TEMPLATE, clientRegistration.getUuidId().toString()));
        client.setIcon(clientRegistration.getLoginButtonIcon());
        return client;
    }

    public static List<OAuth2ClientRegistrationInfo> toClientRegistrations(OAuth2ClientsParams oAuth2Params) {
        return oAuth2Params.getOAuth2DomainDtos().stream()
                .flatMap(domainParams -> domainParams.getClientRegistrations().stream()
                        .map(clientRegistrationDto -> OAuth2Utils.toClientRegistration(oAuth2Params.isEnabled(),
                                domainParams.getDomainName(),
                                domainParams.getRedirectUriTemplate(),
                                clientRegistrationDto)
                        ))
                .collect(Collectors.toList());
    }

    public static OAuth2ClientsParams toOAuth2Params(List<OAuth2ClientRegistrationInfo> clientRegistrations) {
        Map<String, OAuth2ClientsDomainParams> domainParamsMap = new HashMap<>();
        boolean enabled = true;
        for (OAuth2ClientRegistrationInfo clientRegistration : clientRegistrations) {
            enabled = clientRegistration.isEnabled();
            String domainName = clientRegistration.getDomainName();
            OAuth2ClientsDomainParams domainParams = domainParamsMap.computeIfAbsent(domainName,
                    key -> new OAuth2ClientsDomainParams(domainName, clientRegistration.getRedirectUriTemplate(), new ArrayList<>())
            );
            domainParams.getClientRegistrations()
                    .add(toClientRegistrationDto(clientRegistration));
        }
        return new OAuth2ClientsParams(enabled, new ArrayList<>(domainParamsMap.values()));
    }

    public static ClientRegistrationDto toClientRegistrationDto(OAuth2ClientRegistrationInfo oAuth2ClientRegistrationInfo) {
        return ClientRegistrationDto.builder()
                .id(oAuth2ClientRegistrationInfo.getId())
                .createdTime(oAuth2ClientRegistrationInfo.getCreatedTime())
                .mapperConfig(oAuth2ClientRegistrationInfo.getMapperConfig())
                .clientId(oAuth2ClientRegistrationInfo.getClientId())
                .clientSecret(oAuth2ClientRegistrationInfo.getClientSecret())
                .authorizationUri(oAuth2ClientRegistrationInfo.getAuthorizationUri())
                .accessTokenUri(oAuth2ClientRegistrationInfo.getAccessTokenUri())
                .scope(oAuth2ClientRegistrationInfo.getScope())
                .userInfoUri(oAuth2ClientRegistrationInfo.getUserInfoUri())
                .userNameAttributeName(oAuth2ClientRegistrationInfo.getUserNameAttributeName())
                .jwkSetUri(oAuth2ClientRegistrationInfo.getJwkSetUri())
                .clientAuthenticationMethod(oAuth2ClientRegistrationInfo.getClientAuthenticationMethod())
                .loginButtonLabel(oAuth2ClientRegistrationInfo.getLoginButtonLabel())
                .loginButtonIcon(oAuth2ClientRegistrationInfo.getLoginButtonIcon())
                .additionalInfo(oAuth2ClientRegistrationInfo.getAdditionalInfo())
                .build();
    }

    private static OAuth2ClientRegistrationInfo toClientRegistration(boolean enabled, String domainName,
                                                                     String redirectUriTemplate,
                                                                     ClientRegistrationDto clientRegistrationDto) {
        OAuth2ClientRegistrationInfo clientRegistration = new OAuth2ClientRegistrationInfo();
        clientRegistration.setId(clientRegistrationDto.getId());
        clientRegistration.setEnabled(enabled);
        clientRegistration.setCreatedTime(clientRegistrationDto.getCreatedTime());
        clientRegistration.setDomainName(domainName);
        clientRegistration.setRedirectUriTemplate(redirectUriTemplate);
        clientRegistration.setMapperConfig(clientRegistrationDto.getMapperConfig());
        clientRegistration.setClientId(clientRegistrationDto.getClientId());
        clientRegistration.setClientSecret(clientRegistrationDto.getClientSecret());
        clientRegistration.setAuthorizationUri(clientRegistrationDto.getAuthorizationUri());
        clientRegistration.setAccessTokenUri(clientRegistrationDto.getAccessTokenUri());
        clientRegistration.setScope(clientRegistrationDto.getScope());
        clientRegistration.setUserInfoUri(clientRegistrationDto.getUserInfoUri());
        clientRegistration.setUserNameAttributeName(clientRegistrationDto.getUserNameAttributeName());
        clientRegistration.setJwkSetUri(clientRegistrationDto.getJwkSetUri());
        clientRegistration.setClientAuthenticationMethod(clientRegistrationDto.getClientAuthenticationMethod());
        clientRegistration.setLoginButtonLabel(clientRegistrationDto.getLoginButtonLabel());
        clientRegistration.setLoginButtonIcon(clientRegistrationDto.getLoginButtonIcon());
        clientRegistration.setAdditionalInfo(clientRegistrationDto.getAdditionalInfo());
        return clientRegistration;
    }
}
