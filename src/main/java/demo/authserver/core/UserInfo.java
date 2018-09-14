package demo.authserver.core;

import lombok.Data;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Data
public class UserInfo extends User {

    private static final long serialVersionUID = 5231134212346077681L;

    private Long id;
    private String avatar;
    private String phone;
    private String mail;
    private String displayName;

    public UserInfo(String username, String password, boolean enabled,
                    boolean accountNonExpired, boolean credentialsNonExpired,
                    boolean accountNonLocked,
                    Collection authorities,
                    Long id,
                    String avatar,
                    String mail,
                    String phone,
                    String displayName) {

        super(username, password, enabled, accountNonExpired,
                credentialsNonExpired, accountNonLocked, authorities);

        this.id = id;
        this.avatar = avatar;
        this.mail = mail;
        this.phone = phone;
        this.displayName = displayName;
    }
}
