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
package org.thingsboard.server.dao.service;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.thingsboard.server.common.data.oauth2.*;
import org.thingsboard.server.dao.oauth2.OAuth2Service;
import org.thingsboard.server.dao.oauth2.OAuth2Utils;

import java.util.*;
import java.util.stream.Collectors;

import static org.thingsboard.server.dao.oauth2.OAuth2Utils.toClientRegistrations;

public class BaseOAuth2ServiceTest extends AbstractServiceTest {

    @Autowired
    protected OAuth2Service oAuth2Service;

    @Before
    public void beforeRun() {
        Assert.assertTrue(oAuth2Service.findAllClientRegistrations().isEmpty());
    }

    @After
    public void after() {
        oAuth2Service.findAllClientRegistrations().forEach(clientRegistration -> {
            oAuth2Service.deleteClientRegistrationById(clientRegistration.getId());
        });
        Assert.assertTrue(oAuth2Service.findAllClientRegistrations().isEmpty());
    }

    @Test
    public void testCreateNewParams() {
        OAuth2ClientRegistrationInfo clientRegistration = validClientRegistration("domain-name");
        OAuth2ClientsParams savedOAuth2Params = oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Collections.singletonList(clientRegistration)));
        Assert.assertNotNull(savedOAuth2Params);

        List<OAuth2ClientRegistrationInfo> savedClientRegistrations = OAuth2Utils.toClientRegistrations(savedOAuth2Params);
        Assert.assertEquals(1, savedClientRegistrations.size());

        OAuth2ClientRegistrationInfo savedClientRegistration = savedClientRegistrations.get(0);
        Assert.assertNotNull(savedClientRegistration.getId());
        clientRegistration.setId(savedClientRegistration.getId());
        clientRegistration.setCreatedTime(savedClientRegistration.getCreatedTime());
        Assert.assertEquals(clientRegistration, savedClientRegistration);

        oAuth2Service.deleteClientRegistrationsByDomain("domain-name");
    }

    @Test
    public void testFindDomainParams() {
        OAuth2ClientRegistrationInfo clientRegistration = validClientRegistration();
        oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Collections.singletonList(clientRegistration)));

        OAuth2ClientsParams foundOAuth2Params = oAuth2Service.findOAuth2Params();
        Assert.assertEquals(1, foundOAuth2Params.getOAuth2DomainDtos().size());
        Assert.assertEquals(1, oAuth2Service.findAllClientRegistrations().size());

        List<OAuth2ClientRegistrationInfo> foundClientRegistrations = OAuth2Utils.toClientRegistrations(foundOAuth2Params);
        OAuth2ClientRegistrationInfo foundClientRegistration = foundClientRegistrations.get(0);
        Assert.assertNotNull(foundClientRegistration);
        clientRegistration.setId(foundClientRegistration.getId());
        clientRegistration.setCreatedTime(foundClientRegistration.getCreatedTime());
        Assert.assertEquals(clientRegistration, foundClientRegistration);
    }

    @Test
    public void testGetOAuth2Clients() {
        String testDomainName = "test_domain";
        OAuth2ClientRegistrationInfo first = validClientRegistration(testDomainName);
        first.setEnabled(true);
        OAuth2ClientRegistrationInfo second = validClientRegistration(testDomainName);
        second.setEnabled(true);

        oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Collections.singletonList(first)));
        oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Collections.singletonList(second)));

        List<OAuth2ClientInfo> oAuth2Clients = oAuth2Service.getOAuth2Clients(, testDomainName);

        Set<String> actualLabels = new HashSet<>(Arrays.asList(first.getLoginButtonLabel(),
                second.getLoginButtonLabel()));

        Set<String> foundLabels = oAuth2Clients.stream().map(OAuth2ClientInfo::getName).collect(Collectors.toSet());
        Assert.assertEquals(actualLabels, foundLabels);
    }

    @Test
    public void testGetEmptyOAuth2Clients() {
        String testDomainName = "test_domain";
        OAuth2ClientRegistrationInfo tenantClientRegistration = validClientRegistration(testDomainName);
        OAuth2ClientRegistrationInfo sysAdminClientRegistration = validClientRegistration(testDomainName);
        oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Collections.singletonList(tenantClientRegistration)));
        oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Collections.singletonList(sysAdminClientRegistration)));
        List<OAuth2ClientInfo> oAuth2Clients = oAuth2Service.getOAuth2Clients(, "random-domain");
        Assert.assertTrue(oAuth2Clients.isEmpty());
    }

    @Test
    public void testDeleteOAuth2ClientRegistration() {
        OAuth2ClientRegistrationInfo first = validClientRegistration();
        OAuth2ClientRegistrationInfo second = validClientRegistration();

        OAuth2ClientsParams savedFirstOAuth2Params = oAuth2Service.saveOAuth2Params(
                OAuth2Utils.toOAuth2Params(Collections.singletonList(first)));
        OAuth2ClientsParams savedSecondOAuth2Params = oAuth2Service.saveOAuth2Params(
                OAuth2Utils.toOAuth2Params(Collections.singletonList(second)));

        OAuth2ClientRegistrationInfo savedFirstRegistration = toClientRegistrations(savedFirstOAuth2Params).get(0);
        OAuth2ClientRegistrationInfo savedSecondRegistration = toClientRegistrations(savedSecondOAuth2Params).get(0);

        oAuth2Service.deleteClientRegistrationById(savedFirstRegistration.getId());
        List<OAuth2ClientRegistrationInfo> foundRegistrations = oAuth2Service.findAllClientRegistrations();
        Assert.assertEquals(1, foundRegistrations.size());
        Assert.assertEquals(savedSecondRegistration, foundRegistrations.get(0));
    }

    @Test
    public void testDeleteDomainOAuth2ClientRegistrations() {
        oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Arrays.asList(
                validClientRegistration("domain1"),
                validClientRegistration("domain1"),
                validClientRegistration("domain2")
        )));
        oAuth2Service.saveOAuth2Params(OAuth2Utils.toOAuth2Params(Arrays.asList(
                validClientRegistration("domain2")
        )));
        Assert.assertEquals(4, oAuth2Service.findAllClientRegistrations().size());
        OAuth2ClientsParams oAuth2Params = oAuth2Service.findOAuth2Params();
        List<OAuth2ClientRegistrationInfo> clientRegistrations = toClientRegistrations(oAuth2Params);
        Assert.assertEquals(2, oAuth2Params.getOAuth2DomainDtos().size());
        Assert.assertEquals(4, clientRegistrations.size());

        oAuth2Service.deleteClientRegistrationsByDomain("domain1");
        Assert.assertEquals(2, oAuth2Service.findAllClientRegistrations().size());
        Assert.assertEquals(1, oAuth2Service.findOAuth2Params().getOAuth2DomainDtos().size());
        Assert.assertEquals(2, toClientRegistrations(oAuth2Service.findOAuth2Params()).size());
    }

    private OAuth2ClientRegistrationInfo validClientRegistration() {
        return validClientRegistration(UUID.randomUUID().toString());
    }

    private OAuth2ClientRegistrationInfo validClientRegistration(String domainName) {
        OAuth2ClientRegistrationInfo clientRegistration = new OAuth2ClientRegistrationInfo();
        clientRegistration.setDomainName(domainName);
        clientRegistration.setMapperConfig(
                OAuth2MapperConfig.builder()
                        .allowUserCreation(true)
                        .activateUser(true)
                        .type(MapperType.CUSTOM)
                        .custom(
                                OAuth2CustomMapperConfig.builder()
                                        .url("UUID.randomUUID().toString()")
                                        .build()
                        )
                        .build()
        );
        clientRegistration.setClientId(UUID.randomUUID().toString());
        clientRegistration.setClientSecret(UUID.randomUUID().toString());
        clientRegistration.setAuthorizationUri(UUID.randomUUID().toString());
        clientRegistration.setAccessTokenUri(UUID.randomUUID().toString());
        clientRegistration.setRedirectUriTemplate(UUID.randomUUID().toString());
        clientRegistration.setScope(Arrays.asList(UUID.randomUUID().toString(), UUID.randomUUID().toString()));
        clientRegistration.setUserInfoUri(UUID.randomUUID().toString());
        clientRegistration.setUserNameAttributeName(UUID.randomUUID().toString());
        clientRegistration.setJwkSetUri(UUID.randomUUID().toString());
        clientRegistration.setClientAuthenticationMethod(UUID.randomUUID().toString());
        clientRegistration.setLoginButtonLabel(UUID.randomUUID().toString());
        clientRegistration.setLoginButtonIcon(UUID.randomUUID().toString());
        clientRegistration.setAdditionalInfo(mapper.createObjectNode().put(UUID.randomUUID().toString(), UUID.randomUUID().toString()));
        return clientRegistration;
    }
}
