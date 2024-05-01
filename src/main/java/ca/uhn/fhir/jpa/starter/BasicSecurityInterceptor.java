package ca.uhn.fhir.jpa.starter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.security.Key;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
//import io.jsonwebtoken.security.SignatureException;
import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.math.BigInteger;

@Interceptor
public class BasicSecurityInterceptor extends AuthorizationInterceptor {
	/**
	 * This interceptor implements HTTP Basic Auth, which specifies that
	 * a username and password are provided in a header called Authorization.
	 */

	private static final String SECRET_KEY = "14dadd1cbcaf8c19db3666aa5c172f0a4d22d17e8f4a34069d74e987b719e4a0";
	private static final Key DECODED_SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

	@Hook(Pointcut.SERVER_INCOMING_REQUEST_POST_PROCESSED)
	public boolean incomingRequestPostProcessed(RequestDetails theRequestDetails) throws AuthenticationException {
			String authHeader = theRequestDetails.getHeader("Authorization");

			if (authHeader == null) {
				throw new AuthenticationException("Missing Authorization header");
			}
			String jwtToken = authHeader.substring(7); // Eliminar "Bearer "
			System.out.println("Token: " + jwtToken);
			try {

           		 // Verificar y decodificar el token JWT
				Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(DECODED_SECRET_KEY).build().parseClaimsJws(jwtToken);
        		Claims claims = claimsJws.getBody();
        
				
				// Obtener el rol del usuario del token JWT
				String userRole = (String) claims.get("role");
				System.out.println("User Role: " + userRole);

				String userId = (String) claims.get("id");
				System.out.println("User Id: " + userId);

				// Obtener el rol del usuario del token JWT
				//String userRole = (String) claims.get("role");

				return true;
			} catch (ExpiredJwtException e) {
				// Handle the case where the token is expired but signature is valid
				throw new AuthenticationException("Token is expired");
			} catch (SignatureException e) {
				// Handle the case where the JWT signature does not match
				throw new AuthenticationException("Invalid token");
			} catch (Exception e) {
				// Handle other exceptions
				throw new AuthenticationException("Authentication failed" + e);
			}
		}
	}
