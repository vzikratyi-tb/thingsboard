--
-- Copyright © 2016-2020 The Thingsboard Authors
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

DROP TABLE IF EXISTS oauth2_client_registration;

CREATE TABLE IF NOT EXISTS oauth2_client_registration (
    id                              varchar(31) NOT NULL CONSTRAINT oauth2_client_registration_pkey PRIMARY KEY,
    registration_id                 varchar(255) UNIQUE,
    mapper_config_id                varchar(31),
    client_id                       varchar(255),
    client_secret                   varchar(255),
    authorization_uri               varchar(255),
    token_uri                       varchar(255),
    redirect_uri_template           varchar(255),
    scope                           varchar(255),
    authorization_grant_type        varchar(255),
    user_info_uri                   varchar(255),
    user_name_attribute             varchar(255),
    jwk_set_uri                     varchar(255),
    client_authentication_method    varchar(255),
    client_name                     varchar(255),
    login_button_label              varchar(255),
    login_button_icon               varchar(255)
);

DROP TABLE IF EXISTS oauth2_mapper_config;

CREATE TABLE IF NOT EXISTS oauth2_mapper_config (
    id                                  varchar(31) NOT NULL CONSTRAINT oauth2_mapper_config_pkey PRIMARY KEY,
    allow_user_creation                 boolean,
    activate_user                       boolean,
    type                                varchar(31),
    basic_email_attribute_key           varchar(31),
    basic_first_name_attribute_key      varchar(31),
    basic_last_name_attribute_key       varchar(31),
    basic_tenant_name_strategy          varchar(31),
    basic_tenant_name_pattern           varchar(255),
    basic_customer_name_pattern         varchar(255),
    basic_default_dashboard_name        varchar(255),
    basic_always_full_screen            boolean,
    custom_url                          varchar(255),
    custom_username                     varchar(255),
    custom_password                     varchar(255)
);