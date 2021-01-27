package luke.auctioshopzullgateway.security;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

public class AuthorizationFilter extends BasicAuthenticationFilter {

    private final ValidateJwtUtility validateJwtUtility;

    public AuthorizationFilter(AuthenticationManager authenticationManager, ValidateJwtUtility validateJwtUtility) {
        super(authenticationManager);
        this.validateJwtUtility = validateJwtUtility;
    }

    /**
     * This filter method checks if the token send by the client is valid by parsing the token by the
     * ValidateJwtUtility class.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.replace("Bearer ", "");
        if (!validateToken(token)){
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationToken(token);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        chain.doFilter(request, response);
    }

    private boolean validateToken(String token){
        boolean isValid = true;
        String subject = null;
        String credentials = null;
        Set<GrantedAuthority> authorities = null;

        try{
            subject = validateJwtUtility.extractSubject(token);
            credentials = validateJwtUtility.extractCredentials(token);
            authorities = validateJwtUtility.extractAuthorities(token);
        }catch (Exception ex){
            isValid = false;
        }

        if (subject == null || subject.isEmpty() || credentials == null || credentials.isEmpty() || authorities == null)
            isValid = false;

        if (validateJwtUtility.isTokenExpired(token))
            isValid = false;

        return isValid;
    }

    /**
     *
     * @return UsernamePasswordAuthenticationToken used to set Spring security context.
     */
    private UsernamePasswordAuthenticationToken getAuthenticationToken(String token) {
        return new UsernamePasswordAuthenticationToken(
                validateJwtUtility.extractSubject(token),
                validateJwtUtility.extractCredentials(token),
                validateJwtUtility.extractAuthorities(token));
    }
}
