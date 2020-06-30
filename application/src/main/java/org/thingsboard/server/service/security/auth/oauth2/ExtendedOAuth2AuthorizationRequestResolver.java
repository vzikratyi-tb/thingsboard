package org.thingsboard.server.service.security.auth.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.thingsboard.server.common.data.oauth2.OAuth2ClientRegistration;
import org.thingsboard.server.dao.oauth2.OAuth2Service;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;

@Component
public class ExtendedOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";

    private final AntPathRequestMatcher authorizationRequestMatcher = new AntPathRequestMatcher(
            DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");


    @Autowired
    private OAuth2Service oAuth2Service;
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    private OAuth2AuthorizationRequestResolver baseOAuth2AuthorizationRequestResolver;

    @PostConstruct
    public void init() {
        this.baseOAuth2AuthorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = this.resolveRegistrationId(request);
        return resolve(request, registrationId);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest = baseOAuth2AuthorizationRequestResolver.resolve(request, clientRegistrationId);
        if (authorizationRequest == null) return null;

        OAuth2ClientRegistration clientRegistration = oAuth2Service.getClientRegistration(clientRegistrationId);
        HashMap<String, Object> additionalParameters = new HashMap<>(authorizationRequest.getAdditionalParameters() != null ?
                authorizationRequest.getAdditionalParameters() : Collections.emptyMap());
        if (clientRegistration.getAdditionalAuthParameters() != null) {
            additionalParameters.putAll(clientRegistration.getAdditionalAuthParameters());
        }
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(additionalParameters)
                .build();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) {
            return this.authorizationRequestMatcher
                    .matcher(request).getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }
}
