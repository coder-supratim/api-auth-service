package com.timsoft.services.auth.service.config;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
@SpringBootApplication
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter{


    public static void main(String[] args) {
        SpringApplication.run(WebSecurityConfiguration.class, args);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {

        /*UserDetails user=User.builder().username("user")
                .password(passwordEncoder1().encode("secret"))
                .roles("USER").build();
        UserDetails userAdmin = User.builder().username("admin")
                .password(passwordEncoder1().encode("secret"))
                .roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user,userAdmin);*/

        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails user = User.withUsername("user").password(encoder.encode("secret"))
                .roles("USER").build();
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(user);
        return manager;
    }
    @Bean
    public PasswordEncoder passwordEncoder1() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","/index","/webpublico").permitAll()
                .antMatchers("/webprivado").authenticated()
                .antMatchers("/webadmin").hasRole("ADMIN").and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }
}

