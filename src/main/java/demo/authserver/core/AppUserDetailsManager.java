package demo.authserver.core;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import java.util.List;

public class AppUserDetailsManager extends JdbcUserDetailsManager {

    public static final String DEF_USERS_BY_USERNAME_QUERY =
            "select id,username,password,account_non_expired,credentials_non_expired," +
                    "account_non_locked,enabled,avatar,wxOpenId,mail,phone,display_name "
                    + "from users " + "where username = ?";

    private String usersByUsernameQuery = DEF_USERS_BY_USERNAME_QUERY;

    @Override
    protected List<UserDetails> loadUsersByUsername(String username) {
        return getJdbcTemplate().query(this.usersByUsernameQuery,
                new String[]{username}, (rs, rowNum) -> {
                    Long id = rs.getLong(1);
                    String username1 = rs.getString(2);
                    String password = rs.getString(3);
                    boolean enabled = rs.getBoolean(7);
                    String avatar = rs.getString(8);
                    String mail = rs.getString(10);
                    String phone = rs.getString(11);
                    String displayName = rs.getString(12);
                    return new UserInfo(username1, password, enabled, true, true, true,
                            AuthorityUtils.NO_AUTHORITIES, id, avatar, mail, phone,displayName);
                });
    }

    @Override
    protected UserDetails createUserDetails(String username,
                                            UserDetails userFromUserQuery, List<GrantedAuthority> combinedAuthorities) {
        UserInfo userInfoForUserQuery = (UserInfo) userFromUserQuery;
        return new UserInfo(username, userInfoForUserQuery.getPassword(), userInfoForUserQuery.isEnabled(),
                userInfoForUserQuery.isAccountNonExpired(), userInfoForUserQuery.isCredentialsNonExpired(),
                userInfoForUserQuery.isAccountNonLocked(), combinedAuthorities, userInfoForUserQuery.getId(),
                userInfoForUserQuery.getAvatar(), userInfoForUserQuery.getMail(),
                userInfoForUserQuery.getPhone(),userInfoForUserQuery.getDisplayName());
    }

}
