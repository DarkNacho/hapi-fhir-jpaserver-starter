package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.interceptor.BearerTokenAuthInterceptor;
import ca.uhn.fhir.rest.gclient.TokenClientParam;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// JWT imports
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpMethod;
import io.jsonwebtoken.ExpiredJwtException;

import org.hl7.fhir.r4.model.Bundle;
//---
import org.hl7.fhir.r4.model.IdType;

import org.hl7.fhir.r4.model.Patient;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 * This class is an implementation of the AuthorizationInterceptor class and
 * provides JWT-based security for FHIR requests.
 * It intercepts incoming requests and applies authorization rules based on the
 * JWT token provided in the Authorization header.
 * The class verifies the token, extracts the user role and ID from the token
 * claims, and builds the authorization rules accordingly.
 * If the token is invalid or expired, an AuthenticationException is thrown.
 * If the user role is unauthorized, an AuthenticationException is thrown.
 * If the request path is unauthenticated, a set of default rules is applied.
 */
public class JWTSecurityInterceptor extends AuthorizationInterceptor {

    private static final String SECRET_KEY = System.getenv("SECRET_KEY");
    private static final Key DECODED_SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

    @Override
    public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
        String baseUrl = theRequestDetails.getFhirServerBase();
        String requestPath = theRequestDetails.getRequestPath();
        String requestType = theRequestDetails.getRequestType().toString();

        System.out.println("baseUrl: " + baseUrl);
        System.out.println("requestPath: " + requestPath);
        System.out.println("requestType: " + requestType);

        if (isUnauthenticatedPath(requestPath))
            return new RuleBuilder().allowAll().build();

        if (requestPath.startsWith("Practitioner") && requestType.equals("GET")) // Allow read all Practitioners
            return new RuleBuilder().allow().read().allResources().withAnyId().andThen().denyAll().build();

        String authHeader = theRequestDetails.getHeader("Authorization");
        if (authHeader == null)
            throw new AuthenticationException("Must provide Authorization");

        String jwtToken = authHeader.substring(7); // Remove "Bearer "
        System.out.println("Token: " + jwtToken);

        try {
            Jws<Claims> claimsJws = parseJwtToken(jwtToken);
            Claims claims = claimsJws.getBody();

            String userRole = (String) claims.get("role");
            System.out.println("User Role: " + userRole);
            String userId = (String) claims.get("id");
            System.out.println("User Id: " + userId);

            return buildRulesBasedOnUserRole(userRole, userId, theRequestDetails);
        } catch (ExpiredJwtException e) {
            throw new AuthenticationException("Token is expired");
        } catch (SignatureException e) {
            throw new AuthenticationException("Invalid token");
        } catch (Exception e) {
            throw new AuthenticationException("Authentication failed: " + e.getMessage());
        }
    }

    /**
     * Checks whether a request path is in the list of unauthenticated paths.
     *
     * @param requestPath The HTTP request path to check.
     * @return True if the request path is in the list of unauthenticated paths,
     *         false otherwise.
     *
     *         The unauthenticated paths include:
     *         - "swagger-ui/": The Swagger UI for API documentation.
     *         - "api-docs": The automatically generated API documentation.
     *         - "$get-resource-counts": A FHIR operation to get resource counts.
     *         - "metadata": The FHIR operation to get server metadata.
     *         - "$meta": A FHIR operation to get a resource's metadata.
     *         - "_history": A FHIR operation to get a resource's version history.
     *         - "Practitioner": The FHIR Practitioner resource.
     */
    private boolean isUnauthenticatedPath(String requestPath) {
        return requestPath.equals("swagger-ui/") ||
                requestPath.startsWith("api-docs") ||
                requestPath.equals("$get-resource-counts") ||
                requestPath.equals("metadata") ||
                requestPath.equals("$meta") ||
                requestPath.equals("_history");
    }

    private Jws<Claims> parseJwtToken(String jwtToken) {
        return Jwts.parserBuilder().setSigningKey(DECODED_SECRET_KEY).build().parseClaimsJws(jwtToken);
    }

    private List<IAuthRule> buildRulesBasedOnUserRole(String userRole, String userId,
            RequestDetails theRequestDetails) {
        if ("Admin".equals(userRole)) {
            return new RuleBuilder().allowAll().build();
        } else if ("Patient".equals(userRole)) {
            return buildPatientRules(userId);
        } else if ("Practitioner".equals(userRole)) {
            return buildPractitionerRules(userId, theRequestDetails);
        } else {
            throw new AuthenticationException("Unauthorized role");
        }
    }

    private List<IAuthRule> buildPatientRules(String userId) {
        return new RuleBuilder() // Allow the patient to read their own resources and deny all other requests
                .allow("Read Patient Role").read().allResources()
                .inCompartment("Patient", new IdType("Patient", userId))
                .andThen()
                .allow("Write Patient Role").write().allResources()
                .inCompartment("Patient", new IdType("Patient", userId))
                .andThen()
                .denyAll("Deny all Patient Role")
                .build();
    }

    private List<IAuthRule> buildPractitionerRules(String userId, RequestDetails theRequestDetails) {
        System.out.println("Buscando pacientes con general practitioner id: " + userId);
        var patients = getPatientsWithPractitioner(theRequestDetails, userId);
        System.out.println("Patients con practitioner id tamaño: " + patients.size());

        RuleBuilder ruleBuilder = new RuleBuilder();
        for (var patient : patients) {
            System.out.println("Patient: " + patient.getIdPart());
            ruleBuilder.allow().read().allResources().inCompartment("Patient",
                    new IdType(patient.getResourceType(), patient.getIdPart())).andThen();
            ruleBuilder.allow().write().allResources().inCompartment("Patient",
                    new IdType(patient.getResourceType(), patient.getIdPart())).andThen();
        }

        ruleBuilder.allow().create().resourcesOfType("Patient").withAnyId().andThen();
        ruleBuilder.denyAll("Deny all Practitioner Role");

        return ruleBuilder.build();
    }

    private List<IdType> getPatientsWithPractitioner(RequestDetails theRequestDetails, String practitionerId) {
        // Create JWT token
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "Admin");
        String jwtToken = Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 1000)) // 1 minute
                .signWith(DECODED_SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();

        // Create FHIR context and client
        FhirContext ctx = FhirContext.forR4();
        IGenericClient client = ctx.newRestfulGenericClient(theRequestDetails.getFhirServerBase());

        // Set the bearer token
        client.registerInterceptor(new BearerTokenAuthInterceptor(jwtToken));

        // Send request and parse result
        Bundle response = client.search()
                .forResource(Patient.class)
                .where(new TokenClientParam("general-practitioner").exactly().code(practitionerId))
                .returnBundle(Bundle.class)
                .execute();

        return response.getEntry().stream()
                .map(Bundle.BundleEntryComponent::getResource)
                .filter(resource -> resource instanceof Patient)
                .map(resource -> ((Patient) resource).getIdElement())
                .collect(Collectors.toList());
    }

}
