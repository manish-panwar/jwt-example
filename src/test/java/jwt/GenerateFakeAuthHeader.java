package jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import static java.time.Instant.now;

/**
 * Created by manishk on 4/5/16.
 */
public class GenerateFakeAuthHeader {


    private String fakePrivateKey = "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";
    private String fakeIssuer = "Console";
    private String fakeAudience = "SEG:some_fake_location_group_id";


    private String generateFakeAuthHeader() {
        // Set expiration for 10 years.
        Instant expiry = now().plus(3650, ChronoUnit.DAYS);
        JwtBuilder jwtBuilder = Jwts.builder()
                .setExpiration(Date.from(expiry))
                .setAudience(fakeAudience)
                .setIssuer(fakeIssuer);
        return jwtBuilder
                .signWith(SignatureAlgorithm.RS256, loadPrivateKey(fakePrivateKey))
                .compact();
    }

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

    public static PublicKey loadPublicKey(String publicKey) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }
}
