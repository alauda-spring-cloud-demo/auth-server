package db.migration;

import demo.authserver.core.AppUserDetailsManager;
import demo.authserver.core.UserInfo;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

public class V1_3__InitRootUser implements SpringJdbcMigration {

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        AppUserDetailsManager appUserDetailsManager = new AppUserDetailsManager();
        appUserDetailsManager.setJdbcTemplate(jdbcTemplate);
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        UserInfo user1 = new UserInfo(
                "admin",
                bCryptPasswordEncoder.encode("000000").trim(),
                true,true,true,true,
                AuthorityUtils.createAuthorityList("ROLE_ADMIN"),
                null,"","admin@demo","18811111111","张大大");

        UserInfo user2 = new UserInfo(
                "pmo",
                bCryptPasswordEncoder.encode("000000").trim(),
                true,true,true,true,
                AuthorityUtils.createAuthorityList("ROLE_PMO"),
                null,"","pmo@demo","18822222222","王小小");

        UserInfo user3 = new UserInfo(
                "pm",
                bCryptPasswordEncoder.encode("000000").trim(),
                true,true,true,true,
                AuthorityUtils.createAuthorityList("ROLE_PM"),
                null,"","pm@demo","18833333333","李多多");

        UserInfo user4 = new UserInfo(
                "user",
                bCryptPasswordEncoder.encode("000000").trim(),
                true,true,true,true,
                AuthorityUtils.createAuthorityList("ROLE_USER"),
                null,"","user@demo","18844444444","赵明明");

        appUserDetailsManager.createUser(user1);
        appUserDetailsManager.createUser(user2);
        appUserDetailsManager.createUser(user3);
        appUserDetailsManager.createUser(user4);
    }
}
