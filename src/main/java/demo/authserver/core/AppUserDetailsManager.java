package demo.authserver.core;

import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class AppUserDetailsManager extends JdbcUserDetailsManager {

    private String usersByUsernameQuery = "select id,username,password,account_non_expired,credentials_non_expired," +
            "account_non_locked,enabled,avatar,mail,phone,display_name "
            + "from users " + "where username = ?";

    private String createUserSql = "insert into users (" +
            "username,password,account_non_expired,credentials_non_expired," +
            "account_non_locked,enabled,avatar,mail,phone,display_name) " +
            "values (?,?,?,?,?,?,?,?,?,?)";

    @Override
    protected List<UserDetails> loadUsersByUsername(String username) {
        return getJdbcTemplate().query(this.usersByUsernameQuery,
                new String[]{username}, (rs, rowNum) -> {
                    int idx = 1;
                    Long id = rs.getLong(idx++);
                    String username1 = rs.getString(idx++);
                    String password = rs.getString(idx++);
                    boolean accountNonExpired =rs.getBoolean(idx++);
                    boolean credentialsNonExpired =rs.getBoolean(idx++);
                    boolean accountNonLocked =rs.getBoolean(idx++);
                    boolean enabled = rs.getBoolean(idx++);
                    String avatar = rs.getString(idx++);
                    String mail = rs.getString(idx++);
                    String phone = rs.getString(idx++);
                    String displayName = rs.getString(idx++);

                    return new UserInfo(username1, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked,
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

    @Override
    public void createUser(final UserDetails userDetails) {

        this.validateUserDetails(userDetails);

        UserInfo user = (UserInfo)userDetails;

        this.getJdbcTemplate().update(this.createUserSql, new PreparedStatementSetter() {
            public void setValues(PreparedStatement ps) throws SQLException {
                int idx = 1;
                ps.setString(idx++, user.getUsername());
                ps.setString(idx++, user.getPassword());
                ps.setBoolean(idx++, user.isAccountNonExpired());
                ps.setBoolean(idx++, user.isCredentialsNonExpired());
                ps.setBoolean(idx++, user.isAccountNonLocked());
                ps.setBoolean(idx++, user.isEnabled());
                ps.setString(idx++, user.getAvatar());
                ps.setString(idx++, user.getMail());
                ps.setString(idx++, user.getPhone());
                ps.setString(idx++, user.getDisplayName());
            }
        });
        if (this.getEnableAuthorities()) {
            this.insertUserAuthorities(user);
        }
    }

    private void validateUserDetails(UserDetails user) {
        Assert.isInstanceOf(UserInfo.class,user,"UserDetails must be instance of " + UserInfo.class
                .getCanonicalName());
        Assert.hasText(user.getUsername(), "Username may not be empty or null");
        this.validateAuthorities(user.getAuthorities());
    }

    private void validateAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Assert.notNull(authorities, "Authorities list must not be null");
        Iterator var2 = authorities.iterator();

        while(var2.hasNext()) {
            GrantedAuthority authority = (GrantedAuthority)var2.next();
            Assert.notNull(authority, "Authorities list contains a null entry");
            Assert.hasText(authority.getAuthority(), "getAuthority() method must return a non-empty string");
        }

    }

    private void insertUserAuthorities(UserDetails user) {
        Iterator var2 = user.getAuthorities().iterator();

        while(var2.hasNext()) {
            GrantedAuthority auth = (GrantedAuthority)var2.next();
            this.getJdbcTemplate().update(JdbcUserDetailsManager.DEF_INSERT_AUTHORITY_SQL, new Object[]{user.getUsername(), auth
                    .getAuthority
                    ()});
        }

    }

}
