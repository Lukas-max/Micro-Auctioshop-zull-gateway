package luke.auctioshopzullgateway.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
public class ZuulWebSecurity extends WebSecurityConfigurerAdapter {

    private final ValidateJwtUtility validateJwtUtility;

    public ZuulWebSecurity(ValidateJwtUtility validateJwtUtility) {
        this.validateJwtUtility = validateJwtUtility;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.cors().and()
                .authorizeRequests()
                .antMatchers(HttpMethod.DELETE).hasAuthority("ADMIN")
                .antMatchers(HttpMethod.PUT).hasAuthority("ADMIN")
                .antMatchers(HttpMethod.POST, "/auctioshop-products/api/products/*").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.GET, "/auctioshop-ordersusers/api/users").hasAuthority("ADMIN")
                .antMatchers(HttpMethod.GET, "/auctioshop-ordersusers/api/users/{id}").hasAnyAuthority("ADMIN", "USER")
                .antMatchers(HttpMethod.GET, "/auctioshop-ordersusers/api/order").hasAuthority("ADMIN")
                .anyRequest().permitAll()
                .and().addFilter(new AuthorizationFilter(authenticationManager(), validateJwtUtility));
    }
}
