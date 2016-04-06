package jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import static java.time.Instant.now;
import static org.junit.Assert.assertEquals;

/**
 * Created by manishk on 3/17/2016.
 */
public class JwtExample {

    public static final String AUDIENCE = "SEG:some_fake_location_group_id";
    public static final String ISSUER = "Console";

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
        assertEquals(AUDIENCE, jws.getBody().getAudience());
        assertEquals(ISSUER, jws.getBody().getIssuer());
    }

    @Test
    public void testAsymmetric() throws Exception {

        KeyPair keyPair = RsaProvider.generateKeyPair();

        // Sign using private key. This is simulating a client.
        String authHeader = getJwtBuilder()
                .signWith(SignatureAlgorithm.RS256, keyPair.getPrivate())
                .compact();

        // Validate JWT auth header using public key. This is simulating server side component.
        Jwts.parser()
                .setSigningKey(keyPair.getPublic())
                .requireAudience(AUDIENCE)
                .requireIssuer(ISSUER)
                .parseClaimsJws(authHeader);
    }

    @Test
    public void testWithRsaPublicKeySpec() throws NoSuchAlgorithmException, InvalidKeySpecException {

        // Create RSA Key pair.
        KeyPair keyPair = RsaProvider.generateKeyPair(2048);

        // This is how Console will generate the JWT token. Same token will be passed as "Authorization" header by Console.
        String jwtToken = getJwtBuilder()
                .signWith(SignatureAlgorithm.RS256, keyPair.getPrivate())
                .compact();

        // Get the modulus and exponent from RSA public key. This is what will be given to SEG via REST API or during the installation.
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        String modulus = Base64.getEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());
        String exponent = Base64.getEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());

        // Below code shows how SEG will use the Modulus and exponent that are returned by REST API/Console
        RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(new BigInteger(1, Base64.getDecoder().decode(modulus)),
                new BigInteger(1, Base64.getDecoder().decode(exponent)));
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(rsaPubKey);

        Jws claims = Jwts.parser()
                .setSigningKey(pubKey)
                .requireAudience(AUDIENCE)
                .requireIssuer(ISSUER)
                .parseClaimsJws(jwtToken);
        System.out.println(claims);

    }

    private JwtBuilder getJwtBuilder() {
        Instant expiry = now().plus(3650, ChronoUnit.DAYS);
        return Jwts.builder()
                .setExpiration(Date.from(expiry))
                .setAudience(AUDIENCE)
                .setIssuer(ISSUER);
    }
}
