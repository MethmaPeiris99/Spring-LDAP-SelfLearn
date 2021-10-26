package com.example.springsecurityldapjavabrains;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    /**
     *Method used to tell Spring Security to authenticate with LDAP
     *Configuring the structure of how the user data is stored
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.ldapAuthentication()
                //Distinguished name pattern which indicates how the user information is stored in ldif format
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups") //The Organization Unit which needs to be search for a particular user
                .contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org") //The URL where the LDAP server is hosted
                .and()
                .passwordCompare()
                .passwordEncoder(new LdapShaPasswordEncoder())
                .passwordAttribute("userPassword");
    }

    /**
     * Method used to authorize any request while providing fully authentication
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .formLogin();
    }
}
