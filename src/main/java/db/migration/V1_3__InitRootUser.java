package db.migration;

import demo.authserver.core.AppUserDetailsManager;
import demo.authserver.core.UserInfo;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.List;

public class V1_3__InitRootUser implements SpringJdbcMigration {

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        AppUserDetailsManager appUserDetailsManager = new AppUserDetailsManager();
        appUserDetailsManager.setJdbcTemplate(jdbcTemplate);

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        UserInfo user = new UserInfo("admin",bCryptPasswordEncoder.encode("admin").trim(),true,true,true,true,authorities,
                null,"","admin@demo","18812345678","管理员");
        appUserDetailsManager.createUser(user);
    }
}
