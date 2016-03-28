package jwt;

import io.jsonwebtoken.*;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static java.time.Instant.now;
import static org.junit.Assert.assertEquals;

/**
 * Created by manishk on 3/17/2016.
 */
public class JwtExample {

    @Test
    public void testSymmetric() throws Exception {

        // Generate JWT Auth header using symmetric key(shared secret key between 2 systems). This is simulating a client.
        String symmetricKey = "shHAiduj848^(#$)";
        String authHeader = getJwtBuilder()
                .signWith(SignatureAlgorithm.HS256, symmetricKey.getBytes())
                .compact();

        // Validate JWT auth header. This is simulating server side component.
        Jws<Claims> jws = Jwts.parser().setSigningKey(symmetricKey.getBytes()).parseClaimsJws(authHeader);
        assertEquals(SignatureAlgorithm.HS256.getValue(), jws.getHeader().getAlgorithm());
        assertEquals("Java_SEG", jws.getBody().getId());
        assertEquals("manish", jws.getBody().getIssuer());
    }

    @Test
    public void testAsymmetric() throws Exception {

        // Generate JWT Auth header using asymmetric key(public-private key). This is simulating a client.
        Key key = getCertificateKey();
        String authHeader = getJwtBuilder()
                .signWith(SignatureAlgorithm.RS256, key)
                .compact();

        // Validate JWT auth header. This is simulating server side component.
        Jws<Claims> jws = Jwts.parser().setSigningKey(key).parseClaimsJws(authHeader);
        assertEquals(SignatureAlgorithm.RS256.getValue(), jws.getHeader().getAlgorithm());
        assertEquals("Java_SEG", jws.getBody().getId());
        assertEquals("manish", jws.getBody().getIssuer());
    }

    private JwtBuilder getJwtBuilder() {
        Instant expiry = now().plus(10, ChronoUnit.SECONDS);
        return Jwts.builder()
                .setExpiration(Date.from(expiry))
                .setSubject("Some subject")
                .setId("Java_SEG")
                .setIssuer("manish");
    }

    private Key getCertificateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(Paths.get("src/main/resources/ssl-certs/api-key.p12")), "1111".toCharArray());
        return keyStore.getKey(keyStore.aliases().nextElement(), "1111".toCharArray());
    }
}
