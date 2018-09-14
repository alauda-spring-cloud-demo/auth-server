package demo.authserver.config;

import demo.authserver.core.AppUserDetailsManager;
import demo.authserver.core.UserInfoAuthenticationConverter;
import demo.authserver.core.UserInfoTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@EnableAuthorizationServer
@Configuration
public class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private DataSource dataSource;

    @Value("${oauth2.private-key.path}")
    private String privateKeyPath;

    @Value("${oauth2.private-key.alias}")
    private String privateKeyAlias;

    @Value("${oauth2.private-key.password}")
    private String privateKeyPassword;

    /**
     * JWT方式存储token
     * @return
     */
    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }



    /**
     * 附加用户信息提供类
     * @return
     */
    @Bean
    public UserInfoTokenEnhancer userInfoTokenEnhancer(){
        return new UserInfoTokenEnhancer();
    }

    /**
     * JWT的token生成方式
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(){
        final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();

        //非对称性加密
        KeyStoreKeyFactory keyStoreKeyFactory =
                new KeyStoreKeyFactory(new ClassPathResource(privateKeyPath), privateKeyPassword.toCharArray());
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair(privateKeyAlias));

        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new UserInfoAuthenticationConverter());

        converter.setAccessTokenConverter(defaultAccessTokenConverter);
        return converter;
    }

    /**
     * 配置终节点
     * @param endpoints
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints){
        //身份认证管理
        endpoints.authenticationManager(authenticationManager);

        // 配置TokenServices参数
        DefaultTokenServices tokenServices = new DefaultTokenServices();

        //Client信息服务
        tokenServices.setClientDetailsService(endpoints.getClientDetailsService());

        //Token存储方式
        tokenServices.setTokenStore(jwtTokenStore());
        //支持刷新Token
        tokenServices.setSupportRefreshToken(true);
        //accessToken有效期
        tokenServices.setAccessTokenValiditySeconds( (int) TimeUnit.DAYS.toSeconds(30)); // 30天

        //配置accessToken附加信息
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(userInfoTokenEnhancer(),jwtAccessTokenConverter()));
        tokenServices.setTokenEnhancer(tokenEnhancerChain);

        endpoints.tokenServices(tokenServices);
    }

    /**
     * 认证服务安全配置
     * @param oauthServer
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer){
        oauthServer
                .tokenKeyAccess("permitAll()")//公开/oauth/token的接口
                .checkTokenAccess("permitAll()"); //url:/oauth/check_token allow check token
//                .allowFormAuthenticationForClients();
    }

    /**
     * 配置client服务
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }

    @Configuration
    protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
        @Autowired
        DataSource dataSource;

        @Bean
        public AppUserDetailsManager appUserDetailsManager(){
            AppUserDetailsManager appUserDetailsManager = new AppUserDetailsManager();
            appUserDetailsManager.setDataSource(dataSource);
            return appUserDetailsManager;
        }

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder(){
            return new BCryptPasswordEncoder();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .userDetailsService(appUserDetailsManager())
                    .passwordEncoder(bCryptPasswordEncoder());
        }

        @Bean
        public FilterRegistrationBean filterRegistrationBean() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowCredentials(true);
            config.addAllowedOrigin("*");
            config.addAllowedHeader("*");
            config.addAllowedMethod("*");
            source.registerCorsConfiguration("/**", config);
            FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
            bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
            return bean;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .antMatchers("/","/home","/health")
                    .permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .and()
                .logout()
                    .logoutUrl("/logout")
                    .permitAll();

        }
    }
}
