package db.migration;

import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

import java.util.*;

public class V1_4__InitAppClient implements SpringJdbcMigration {

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        JdbcClientDetailsService jdbcClientDetailsService = new JdbcClientDetailsService(jdbcTemplate.getDataSource());

        BaseClientDetails client = new BaseClientDetails();

        client.setClientId("demo_client");
        client.setClientSecret("demo_secret");

        Set<String> grantAuthorizedGrantTypes = new HashSet<>();
        grantAuthorizedGrantTypes.add("implicit");
        grantAuthorizedGrantTypes.add("refresh_token");
        grantAuthorizedGrantTypes.add("password");
        grantAuthorizedGrantTypes.add("authorization_code");

        client.setAuthorizedGrantTypes(grantAuthorizedGrantTypes);

        Set<String> scopes = new HashSet<>();
        scopes.add("read_scope");
        scopes.add("write_scope");
        scopes.add("admin_scope");

        client.setScope(scopes);

        List<String> resourceIds = new ArrayList<>();
        resourceIds.add("oauth2-resource");

        client.setResourceIds(resourceIds);

        client.setAdditionalInformation(new HashMap<>());

        jdbcClientDetailsService.addClientDetails(client);
    }
}
