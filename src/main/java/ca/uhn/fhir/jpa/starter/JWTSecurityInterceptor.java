package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import org.hl7.fhir.instance.model.api.IIdType;
import org.hl7.fhir.r4.model.IdType;


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
import java.util.List;
import ca.uhn.fhir.rest.param.ReferenceParam;
import ca.uhn.fhir.rest.param.ReferenceOrListParam;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import org.hl7.fhir.r4.model.Patient;
import org.hl7.fhir.r4.model.Practitioner;
import org.hl7.fhir.r4.model.Reference;

public class JWTSecurityInterceptor extends AuthorizationInterceptor {

	private static final String SECRET_KEY = "14dadd1cbcaf8c19db3666aa5c172f0a4d22d17e8f4a34069d74e987b719e4a0";
	private static final Key DECODED_SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

    @Override
    public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
        String baseUrl = theRequestDetails.getFhirServerBase();
        String requestPath = theRequestDetails.getRequestPath();
        
        System.out.println("baseUrl: " + baseUrl);
        System.out.println("requestPath: " + requestPath);

		
        if (requestPath.equals("swagger-ui/") || 
            requestPath.equals("otra/pagina/permitida") || 
            requestPath.startsWith("api-docs") ||
            requestPath.equals("$get-resource-counts") ||
            requestPath.equals("metadata") ||
            requestPath.equals("$meta") ||
            requestPath.equals("_history"))
                return new RuleBuilder().allowAll().build();
            
        
        String authHeader = theRequestDetails.getHeader("Authorization");
        if (authHeader == null) {
            if ("Practitioner".equals(theRequestDetails.getResourceName())) 
                // Si es un recurso Practitioner, permitimos la lectura
                return new RuleBuilder()
                    .allow().read().resourcesOfType(Practitioner.class).withAnyId().andThen()
                    .denyAll()
                    .build();
            // Si no hay encabezado de autorización, lanzamos una excepción de autenticación
            throw new AuthenticationException("Must provide Authorization");
        }
        String jwtToken = authHeader.substring(7); // Eliminar "Bearer "

		System.out.println("Token: " + jwtToken);
		
        try 
        {
     		// Verificar y decodificar el token JWT
		    Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(DECODED_SECRET_KEY).build().parseClaimsJws(jwtToken);
            Claims claims = claimsJws.getBody();

		    // Obtener el rol del usuario del token JWT
		    String userRole = (String) claims.get("role");
		    System.out.println("User Role: " + userRole);
    	    String userId = (String) claims.get("id");
		    System.out.println("User Id: " + userId);


            // Construir reglas de autorización según el rol del usuario
            if ("admin".equals(userRole)) {
                // Si el usuario es un administrador, permitir todas las operaciones en todos los recursos
                return new RuleBuilder().allowAll().build();
            } else if ("patient".equals(userRole)) {
                // Construir reglas de autorización para el paciente
                return new RuleBuilder()
                    .allow()
                    .read()
                    .allResources()
                    .inCompartment("Patient", new IdType("Patient", userId))
                    .andThen()
                    .denyAll()
                    .build();
            } else {
                // Otros roles pueden tener sus propias reglas de autorización
                // Implementa las reglas según sea necesario
                throw new AuthenticationException("Unauthorized role");
            }
        } catch (ExpiredJwtException e) {
            // Handle the case where the token is expired but signature is valid
            throw new AuthenticationException("Token is expired");
        } catch (SignatureException e) {
            // Handle the case where the JWT signature does not match
            throw new AuthenticationException("Invalid token");
        } catch (Exception e) {
            // Handle other exceptions
            throw new AuthenticationException("Authentication failed", e);
        }
    }
}
