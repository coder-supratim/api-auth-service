package com.timsoft.services.auth.service.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;
    @Autowired
    private TokenStore tokenStore;

    @Value("${jwt.clientId:device-mngr-client-10BX3ELTTS}")
    private String clientId;

    @Value("${jwt.client-secret:secretX}")
    private String clientSecret;

    @Value("${jwt.signing-key:667432890}")
    private String jwtSigningKey;

    @Value("${jwt.accessTokenValiditySeconds:3600}") // 1 hours
    private int accessTokenValiditySeconds;

    @Value("${jwt.authorizedGrantTypes:password,authorization_code,refresh_token, implicit}")
    private String[] authorizedGrantTypes;

    @Value("${jwt.authorizedScopes:read,write}")
    private String[] scopes;

    @Value("${jwt.refreshTokenValiditySeconds:2592000}") // 30 days
    private int refreshTokenValiditySeconds;

    @Override
    public void configure (ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory ()
                .withClient (clientId)
                .authorizedGrantTypes (authorizedGrantTypes)
                .authorities ("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT", "USER")
                .scopes (scopes)
                .autoApprove (true)
                .secret ("{noop}"+clientSecret);
    }
    //PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    @Override
    public void configure (AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager (authenticationManager)
                .tokenStore (tokenStore);
    }
    @Bean
    public TokenStore tokenStore () {
        return new InMemoryTokenStore();
    }
}
