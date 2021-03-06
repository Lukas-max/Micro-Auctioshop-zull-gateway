package luke.auctioshopzullgateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class validates JSON Web token send by the client for:
 * - subject (user username)
 * - credentials (password)
 * - authorities (admin, user authorities etc..)
 * - expiration time of the token.
 *
 * It parses the token for claims ane extracts this values as the method names say.
 */
@Service
public class ValidateJwtUtility {

    private Logger logger = LoggerFactory.getLogger(ValidateJwtUtility.class);

    @Value("${shop.token}")
    private String SECRET_KEY;

    public String extractSubject(String token) {
        return extractClaim(token).getSubject();
    }

    public String extractCredentials(String token){
        return extractClaim(token).get("credentials", String.class);
    }

    public Set<GrantedAuthority> extractAuthorities(String token){
        String[] scope = extractClaim(token)
                .get("authority", String.class)
                .split(",");

        return Arrays.stream(scope)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractClaim(token)
                    .getExpiration()
                    .before(new Date());

        }catch (Exception ex){
            return false;
        }
    }

    private Claims extractClaim(String token) {
        Claims claims = null;

            try{
                claims = Jwts.parser()
                        .setSigningKey(SECRET_KEY)
                        .parseClaimsJws(token)
                        .getBody();

            }catch (Exception ex){
                logger.warn("Login attempt with invalid Json Web token.");
            }
            return claims;
    }
}
