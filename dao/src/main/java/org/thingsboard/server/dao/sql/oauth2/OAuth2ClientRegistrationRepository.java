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
package org.thingsboard.server.dao.sql.oauth2;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.thingsboard.server.common.data.oauth2.SchemeType;
import org.thingsboard.server.dao.model.sql.ClientRegistrationToDomainCompositeKey;
import org.thingsboard.server.dao.model.sql.OAuth2ClientRegistrationEntity;
import org.thingsboard.server.dao.model.sql.OAuth2ClientRegistrationInfoEntity;

import java.util.List;
import java.util.UUID;

public interface OAuth2ClientRegistrationRepository extends CrudRepository<OAuth2ClientRegistrationEntity, UUID> {
    @Query("SELECT OAuth2ClientRegistrationInfoEntity " +
            "FROM OAuth2ClientRegistrationInfoEntity cr " +
            "LEFT JOIN OAuth2ClientRegistrationEntity cr_to_domain on cr.id = cr_to_domain.clientRegistrationId " +
            "WHERE cr_to_domain.domainName = :domainName " +
            "AND cr_to_domain.domainScheme = :domainScheme")
    List<OAuth2ClientRegistrationInfoEntity> findAllByDomainSchemeAndName(@Param("domainScheme") SchemeType domainScheme,
                                                                          @Param("domainName") String domainName);
}
