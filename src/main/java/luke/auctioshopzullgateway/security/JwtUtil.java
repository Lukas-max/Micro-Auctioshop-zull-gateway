package luke.auctioshopzullgateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;


@Service
public class JwtUtil {

    @Value("${shop.token}")
    private String SECRET_KEY;

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractSubject(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

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

    private boolean isTokenExpired(String token) {
        return extractClaim(token)
                .getExpiration()
                .before(new Date());
    }

    private Claims extractClaim(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }
}
