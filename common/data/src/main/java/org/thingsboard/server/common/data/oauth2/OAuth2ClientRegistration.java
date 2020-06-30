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
package org.thingsboard.server.common.data.oauth2;

import lombok.*;
import org.thingsboard.server.common.data.BaseData;
import org.thingsboard.server.common.data.id.OAuth2IntegrationId;

import java.util.HashMap;
import java.util.Map;

@EqualsAndHashCode
@Data
@ToString(exclude = {"clientSecret"})
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2ClientRegistration {

    private String registrationId;
    private OAuth2MapperConfig mapperConfig;
    private String clientId;
    private String clientSecret;
    private String authorizationUri;
    private String tokenUri;
    private String redirectUriTemplate;
    private String scope;
    private String userInfoUri;
    private String userNameAttributeName;
    private String jwkSetUri;
    private String clientAuthenticationMethod;
    private String clientName;
    private String loginButtonLabel;
    private String loginButtonIcon;
    private Map<String, String> additionalAuthParameters;
}
