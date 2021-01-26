package luke.auctioshopzullgateway.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
public class ZuulWebSecurity extends WebSecurityConfigurerAdapter {

    private final JwtUtil jwtUtil;

    public ZuulWebSecurity(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.cors().and()
                .authorizeRequests()
                .antMatchers(HttpMethod.DELETE).hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT).hasRole("ADMIN")
                .antMatchers(HttpMethod.POST, "/auctioshop-products/api/products/*").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/auctioshop-ordersusers/api/users").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/auctioshop-ordersusers/api/users/{id}").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.GET, "/auctioshop-ordersusers/api/order").hasRole("ADMIN")
                .anyRequest().permitAll()
                .and().addFilter(new AuthorizeUserFilter(authenticationManager(), jwtUtil));
    }
}
