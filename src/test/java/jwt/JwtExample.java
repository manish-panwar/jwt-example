package jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
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

    private final String modulus = "AL95wMahFHS+IgwzuVlkg1X2C86r5vnySAkaRW9VAnY9k1GHAiy9T5oddqI47n1UUcNrnMMcBXT+SKzkH/Y/N1/0AU05KoUZCweJWvs2pDde+7wjoaYr0wJyL3AxpkkecbqYwNTH9WUi6pXe2W3MMaFLpGSyYzEwuCvhCyOPKzGK7iUwOpEmgq84iX+3eLcErgtUN6mLvfDGXK/uiVPn99QdTOgiszbR9Emx9tMpc7lMYckcp5dccUsaF6n+eyY+5xdsldcRm3MYSTiTTkciHGD3qJWHyy49FRdXlPmHnpdf+1ytjdUH8nexZZkCpy6K5P3c3Z8jtNEBXWsEYZn2ie8=";
    private final String fakePrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/ecDGoRR0viIMM7lZZINV9gvOq+b58kgJGkVvVQJ2PZNRhwIsvU+aHXaiOO59VFHDa5zDHAV0/kis5B/2Pzdf9AFNOSqFGQsHiVr7NqQ3Xvu8I6GmK9MCci9wMaZJHnG6mMDUx/VlIuqV3tltzDGhS6RksmMxMLgr4Qsjjysxiu4lMDqRJoKvOIl/t3i3BK4LVDepi73wxlyv7olT5/fUHUzoIrM20fRJsfbTKXO5TGHJHKeXXHFLGhep/nsmPucXbJXXEZtzGEk4k05HIhxg96iVh8suPRUXV5T5h56XX/tcrY3VB/J3sWWZAqcuiuT93N2fI7TRAV1rBGGZ9onvAgMBAAECggEBALEeYAudD34aLwaYhhjB2JeYvT1VWJjW3HnHGnms6lUUCoU83O8jw1GtdYMEJOA8MlIR5nW5IvchDXsYntQ7j+6rmNSlT8bE7qXvEgEVf3xU2Yokb7B2E3/MvkMLOmWiytMv4Bg0S7RdQyCVfw2I+FPa09vuA8GJ7qNwTcx78Bmnb4a0AxHiYylaCTwPqrIJnErZMsJpGOlH/AIEovB5aQWcX2OR2ftN/fulg4R/kg6vf4V5YA3g9ZG2Jqias/agA+9ocSQn2oFRo1lwItGGE93TYrB2TUIftJWTSYW+KbyBDQ08i7Hes+GmqyXZK6RoOJRVixfS1n9lhGHHVjFfWlECgYEA4jIdC5TQ6O4PDGXEpklNRttv3ko/mM5Ea8koHnNkAMjCDPRKUKbteRPPVQHFDY/8SQ50Tqzg6c5m/gunOU0JbHqPobAAhyugtIydLTYymZfhOlAYra8nvmKtAb0PUFVb2CKo5ujdYQScblyFjrEM+IQw6QgcSLdneNKiSL4pNokCgYEA2LR7ZkNIxX/06GpcIKHZnW51naLDBkbs9W668bt3m2EogzwluT9ZzGd3sEF2Es1FG6Jxw+D/fqRF2IDwpyk11voIp0LPh6IZ0709OkpdytpAl+rVXzoe4i0DU2MVsUAotYd7uA2A9sDkurZwKLqN78zuuY/UUhC5hutP5q4YnrcCgYBVRVMRxJ4k0Wm24L6LeWK6bYr0n8Tt1ASTJZgMMq/mY8hTndxOHz+yvzcP8sTYYglXeS17Y0y+l2LYLohx34rH7EQtTe5FBrtklQXDv4S/xjPQCdXj0/4Flalm2GDnheZDyn0l329lXZmjORnYOwKKxTqy/q268/j74VvwVE+xEQKBgBENWqx4XPCVmgrz254BvmMB/yVRWnFTAXBqrzE4ZDgI1CxHflxuXL2V4rgu3oCqQGblSHh2awRnHsvjkYxF1OO+txGaU0REAC5GNNwyX+EHfY+2veWJaEa57goQwPM6rjlimNypy10fXqBGnNrHm0WkZaCabcWrZT31pErtpihPAoGAbUPLq/pLaFBMs2USBdBLJH6UYhdz3V+NS1Os5RITiyhhSusjFocHMselSuvrp4LegdcAk/VefokE6b9srgwppfwpykVgJIEhBK07E25eVB2RU4mLlKxbRcnlfj6XMojfNWAWstMQcYd2eFQkhG2hfW+ugYdKZWHaVQJO1vluhe4=";

    public static PrivateKey loadPrivateKey(String privateKey) {
        byte[] clear = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        PrivateKey priv = null;
        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            priv = fact.generatePrivate(keySpec);
            Arrays.fill(clear, (byte) 0);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return priv;
    }

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
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        System.out.println(modulus);
        System.out.println(exponent);
        System.out.println(privateKey);

        // Below code shows how SEG will use the Modulus and exponent that are returned by REST API/Console
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(new BigInteger(1, Base64.getDecoder().decode(modulus)),
                        new BigInteger(1, Base64.getDecoder().decode(exponent))));

        Jws claims = Jwts.parser()
                .setSigningKey(pubKey)
                .requireAudience(AUDIENCE)
                .requireIssuer(ISSUER)
                .parseClaimsJws(jwtToken);
        System.out.println(claims);

    }

    @Test
    public void generateFakeJwtToken() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String jwtToken = generateFakeAuthHeader(7200, ChronoUnit.DAYS);
        System.out.println(jwtToken);

        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(new BigInteger(1, Base64.getDecoder().decode(modulus)),
                        new BigInteger(1, Base64.getDecoder().decode("AQAB"))));

        Jws claims = Jwts.parser()
                .setSigningKey(pubKey)
                .requireAudience(AUDIENCE)
                .requireIssuer(ISSUER)
                .parseClaimsJws(jwtToken);
        System.out.println(claims);
    }

    public String generateFakeAuthHeader(int expiration, ChronoUnit expirationUnit) {
        Instant expiry = now().plus(expiration, expirationUnit);
        JwtBuilder jwtBuilder = Jwts.builder()
                .setExpiration(Date.from(expiry))
                .setAudience(AUDIENCE)
                .setIssuer(ISSUER);
        return jwtBuilder
                .signWith(SignatureAlgorithm.RS256, loadPrivateKey(fakePrivateKey))
                .compact();
    }

    private JwtBuilder getJwtBuilder() {
        Instant expiry = now().plus(7300, ChronoUnit.DAYS);
        return Jwts.builder()
                .setExpiration(Date.from(expiry))
                .setAudience(AUDIENCE)
                .setIssuer(ISSUER);
    }
}
