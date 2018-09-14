CREATE TABLE oauth_client_details (
  id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
  client_id VARCHAR(128),
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);
create unique index ix_oauth_client_details_client on oauth_client_details (client_id);