/**
 * Copyright © 2016-2020 The Thingsboard Authors
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.service.security.auth.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.thingsboard.server.common.data.User;
import org.thingsboard.server.common.data.audit.ActionType;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.data.security.UserCredentials;
import org.thingsboard.server.dao.user.UserService;
import org.thingsboard.server.service.security.auth.JwtAuthenticationToken;
import org.thingsboard.server.service.security.model.SecurityUser;
import org.thingsboard.server.service.security.model.UserPrincipal;
import org.thingsboard.server.service.security.model.token.JwtTokenFactory;
import org.thingsboard.server.service.security.model.token.RawAccessJwtToken;

@Component
@SuppressWarnings("unchecked")
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtTokenFactory tokenFactory;
    private final JwtDecoderFactory<ClientRegistration> jwtDecoderFactory;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final UserService userService;

    @Autowired
    public JwtAuthenticationProvider(JwtTokenFactory tokenFactory, JwtDecoderFactory<ClientRegistration> jwtDecoderFactory, ClientRegistrationRepository clientRegistrationRepository, UserService userService) {
        this.tokenFactory = tokenFactory;
        this.jwtDecoderFactory = jwtDecoderFactory;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, "No authentication data provided");
        if (!(authentication.getDetails() instanceof JwtAuthenticationDetails))
            throw new IllegalArgumentException("Authentication details should be of type " + JwtAuthenticationDetails.class.getSimpleName() + ".");

        RawAccessJwtToken rawAccessToken = (RawAccessJwtToken) authentication.getCredentials();

        SecurityUser securityUser;
        JwtAuthenticationDetails details = (JwtAuthenticationDetails) authentication.getDetails();
        if (details != null && details.getClientRegistrationId() != null) {
            Object principal = authentication.getPrincipal();
            if (!(principal instanceof UserPrincipal)) {
                throw new BadCredentialsException("Authentication Failed. Bad user principal.");
            }
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(details.getClientRegistrationId());
            JwtDecoder decoder = jwtDecoderFactory.createDecoder(clientRegistration);
            Jwt decoded = decoder.decode(rawAccessToken.getToken());
            String userNameAttributeName = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
            String userName = (String) decoded.getClaims().get(userNameAttributeName);
            UserPrincipal userPrincipal = (UserPrincipal) principal;
            securityUser = createSecurityUserByUsername(userPrincipal, userName);
        } else {
            securityUser = tokenFactory.parseAccessJwtToken(rawAccessToken);
        }
        return new JwtAuthenticationToken(securityUser);


    }

    private SecurityUser createSecurityUserByUsername(UserPrincipal userPrincipal, String username) {
        User user = userService.findUserByEmail(TenantId.SYS_TENANT_ID, username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        UserCredentials userCredentials = userService.findUserCredentialsByUserId(TenantId.SYS_TENANT_ID, user.getId());
        if (userCredentials == null) {
            throw new UsernameNotFoundException("User credentials not found");
        }

        if (user.getAuthority() == null)
            throw new InsufficientAuthenticationException("User has no authority assigned");

        return new SecurityUser(user, userCredentials.isEnabled(), userPrincipal);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
