package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.context.BaseRuntimeChildDefinition;
import ca.uhn.fhir.context.BaseRuntimeElementDefinition;
import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.context.RuntimeResourceDefinition;
import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.api.server.ResponseDetails;
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
import io.jsonwebtoken.ExpiredJwtException;

import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.DocumentReference;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.Patient;
import org.hl7.fhir.r4.model.Reference;
import org.springframework.data.util.Pair;
import org.hl7.fhir.instance.model.api.IBase;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.model.Binary;

/**
 * JWTSecurityInterceptor is an authorization interceptor that handles JWT-based
 * security for FHIR server requests.
 * It extends the AuthorizationInterceptor class and provides methods to build
 * authorization rules based on user roles
 * extracted from JWT tokens.
 * 
 * The interceptor supports the following user roles:
 * - Admin: Full access to all resources.
 * - Patient: Access to their own resources.
 * - Practitioner: Access to resources related to their patients.
 * 
 * The interceptor also handles unauthenticated paths, JWT token parsing, and
 * resource reference checks.
 * 
 * Methods:
 * - buildRuleList(RequestDetails theRequestDetails): Builds a list of
 * authorization rules based on the request details.
 * - getUserRoleAndId(String jwtToken): Extracts the user role and ID from the
 * JWT token.
 * - isUnauthenticatedPath(String requestPath): Checks if the request path is in
 * the list of unauthenticated paths.
 * - parseJwtToken(String jwtToken): Parses the JWT token and returns the
 * claims.
 * - buildRulesBasedOnUserRole(String userRole, String userId, RequestDetails
 * theRequestDetails): Builds authorization rules based on the user role.
 * - buildPatientRules(String userId): Builds authorization rules for the
 * Patient role.
 * - buildPractitionerRules(String userId, RequestDetails theRequestDetails):
 * Builds authorization rules for the Practitioner role.
 * - createFhirClient(String baseUrl): Creates a FHIR client with a JWT token.
 * - generateJwtToken(): Generates a new JWT token.
 * - getPatientsWithPractitioner(RequestDetails theRequestDetails, String
 * practitionerId): Retrieves patients associated with a practitioner.
 * - preProcessResource(RequestDetails theRequest, ResponseDetails
 * theResponseDetails): Pre-processes resources before sending the response.
 * - processBundleResource(RequestDetails theRequest, Bundle bundle): Processes
 * a bundle resource and checks references.
 * - processBinaryResource(RequestDetails theRequest, ResponseDetails
 * theResponseDetails): Processes a binary resource and checks references.
 * - checkReferences(IBaseResource resource, String resourceId): Checks if the
 * resource contains references to the specified resource ID.
 * 
 * Hooks:
 * - SERVER_OUTGOING_RESPONSE: Hook for processing resources before sending the
 * response.
 * 
 * Exceptions:
 * - AuthenticationException: Thrown when authentication fails.
 */
@Interceptor
public class JWTSecurityInterceptor extends AuthorizationInterceptor {

    private static final String SECRET_KEY = System.getenv("SECRET_KEY");
    private static final Key DECODED_SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

    private IGenericClient client = null;
    private String jwtToken = null;
    private Date jwtExpiration = null;

    private Pair<String, String> getUserRoleAndId(String jwtToken) throws AuthenticationException {
        try {
            Jws<Claims> claimsJws = parseJwtToken(jwtToken);
            Claims claims = claimsJws.getBody();

            String userRole = (String) claims.get("role");
            if (userRole == null) {
                throw new AuthenticationException("User role not present in token");
            }
            System.out.println("User Role: " + userRole);

            String userId = (String) claims.get("id");
            if (userId == null && !userRole.equals("Admin")) {
                throw new AuthenticationException("User id not present in token");
            } else if (userId == null && userRole.equals("Admin")) {
                userId = "Admin";
            }
            System.out.println("User Id: " + userId);
            Pair<String, String> userRoleAndId = Pair.of(userRole, userId);

            return userRoleAndId;
        } catch (ExpiredJwtException e) {
            throw new AuthenticationException("Token is expired");
        } catch (SignatureException e) {
            throw new AuthenticationException("Invalid token");
        } catch (Exception e) {
            throw new AuthenticationException("Authentication failed: " + e.getMessage());
        }
    }

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
            Pair<String, String> userRoleAndId = getUserRoleAndId(jwtToken);
            return buildRulesBasedOnUserRole(userRoleAndId.getFirst(), userRoleAndId.getSecond(), theRequestDetails);
        } catch (AuthenticationException e) {
            throw e;
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
                requestPath.equals("_history") ||
                requestPath.startsWith("Practitioner"); // TODO: remove this line, temporary only.
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
        var patients = getPatientsWithPractitioner(theRequestDetails, userId); // get patients that the practitioner has
                                                                               // access
        System.out.println("Patients con practitioner id tamaño: " + patients.size());

        RuleBuilder ruleBuilder = new RuleBuilder(); // Allow the practitioner to read/write their patients
        for (var patient : patients) {
            System.out.println("Patient: " + patient.getIdPart());
            ruleBuilder.allow().read().allResources().inCompartment("Patient",
                    new IdType(patient.getResourceType(), patient.getIdPart())).andThen();
            ruleBuilder.allow().write().allResources().inCompartment("Patient",
                    new IdType(patient.getResourceType(), patient.getIdPart())).andThen();
        }

        ruleBuilder.allow().create().resourcesOfType("Patient").withAnyId().andThen(); // allow create new patient

        ruleBuilder.allow().read().resourcesOfType(Patient.class)
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen();

        ruleBuilder.allow().read().resourcesOfType("Practitioner")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen()
                .allow().write().resourcesOfType("Practitioner")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen();

        ruleBuilder.allow().read().resourcesOfType("Encounter")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen()
                .allow().write().resourcesOfType("Encounter")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen();

        ruleBuilder.allow().read().resourcesOfType("DocumentReference")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen()
                .allow().write().resourcesOfType("DocumentReference")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen();

        ruleBuilder.allow().read().resourcesOfType("Binary").withAnyId().andThen()
                .allow().write().resourcesOfType("Binary").withAnyId().andThen();

        ruleBuilder.allow().read().resourcesOfType("Questionnaire").withAnyId().andThen()
                .allow().write().resourcesOfType("Questionnaire").withAnyId().andThen();

        ruleBuilder.allow().read().resourcesOfType("QuestionnaireResponse")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen()
                .allow().write().resourcesOfType("QuestionnaireResponse")
                .inCompartment("Practitioner", new IdType("Practitioner", userId)).andThen();

        return ruleBuilder.denyAll("Deny all Practitioner Role").build();
    }

    private IGenericClient createFhirClient(String baseUrl) {
        if (client == null || jwtToken == null || jwtExpiration == null || jwtExpiration.before(new Date())) {
            // Create FHIR context and client
            FhirContext ctx = FhirContext.forR4();
            ctx.getRestfulClientFactory().setSocketTimeout(60 * 1000); // 1 minute
            client = ctx.newRestfulGenericClient(baseUrl);

            // Generate a new JWT token
            jwtToken = generateJwtToken();

            // Set the bearer token
            client.registerInterceptor(new BearerTokenAuthInterceptor(jwtToken));
        }

        return client;
    }

    private String generateJwtToken() {
        // Create JWT token
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "Admin");
        jwtExpiration = new Date(System.currentTimeMillis() + 60 * 1000); // 1 minute
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 1000)) // 1 minute
                .signWith(DECODED_SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    private List<IdType> getPatientsWithPractitioner(RequestDetails theRequestDetails, String practitionerId) {

        IGenericClient client = createFhirClient(theRequestDetails.getFhirServerBase());

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

    @Hook(Pointcut.SERVER_OUTGOING_RESPONSE)
    public void preProcessResource(RequestDetails theRequest, ResponseDetails theResponseDetails) {
        if (theResponseDetails.getResponseResource() instanceof Binary) {
            processBinaryResource(theRequest, theResponseDetails);
        }

    }

    private void processBundleResource(RequestDetails theRequest, Bundle bundle) {

        String authHeader = theRequest.getHeader("Authorization");
        if (authHeader == null)
            throw new AuthenticationException("Must provide Authorization");

        String jwtToken = authHeader.substring(7); // Remove "Bearer "
        System.out.println("Token: " + jwtToken);

        try {
            Pair<String, String> userRoleAndId = getUserRoleAndId(jwtToken);
            String userRole = userRoleAndId.getFirst();
            String userId = userRoleAndId.getSecond();
            if ("Admin".equals(userRole)) {
                return;
            }
            for (Bundle.BundleEntryComponent entry : bundle.getEntry()) {
                IBaseResource resource = entry.getResource();
                if (!checkReferences(resource, userId)) {
                    throw new AuthenticationException("Unauthorized access to resource in bundle");
                }
            }
        } catch (AuthenticationException e) {
            throw e;
        }
    }

    private void processBinaryResource(RequestDetails theRequest, ResponseDetails theResponseDetails) {
        Binary binary = (Binary) theResponseDetails.getResponseResource();
        String contentType = binary.getContentType();
        String securityContext = binary.getSecurityContext().getReference().toString();
        String binaryId = binary.getIdElement().getIdPart();
        System.out.println("Content Type: " + contentType);
        System.out.println("Security Context: " + securityContext);
        System.out.println("Binary Id: " + binaryId);

        String authHeader = theRequest.getHeader("Authorization");
        String jwtToken = authHeader.substring(7); // Remove "Bearer "
        System.out.println("Token: " + jwtToken);
        String userId = getUserRoleAndId(jwtToken).getSecond();

        IGenericClient client = createFhirClient(theRequest.getFhirServerBase());
        String referenceResouce = binary.getSecurityContext().getReference();

        DocumentReference resource = client.read()
                .resource(DocumentReference.class)
                .withUrl(referenceResouce)
                .execute();

        if (!checkReferences(resource, userId))
            throw new AuthenticationException("Unauthorized access to binary resource");
    }

    public boolean checkReferences(IBaseResource resource, String resourceId) {
        FhirContext ctx = FhirContext.forR4();
        RuntimeResourceDefinition resourceDef = ctx.getResourceDefinition(resource);
        for (BaseRuntimeChildDefinition childDef : resourceDef.getChildren()) {
            List<IBase> childElements = childDef.getAccessor().getValues(resource);
            for (IBase child : childElements) {
                BaseRuntimeElementDefinition<?> childElementDef = ctx.getElementDefinition(child.getClass());
                if (childElementDef.getName().equals("Reference")) {
                    Reference reference = (Reference) child;
                    if (reference.getReference().contains(resourceId)) {
                        return true;
                    }
                } else if (childElementDef.getChildType() != null && child instanceof IBaseResource) {
                    if (checkReferences((IBaseResource) child, resourceId)) { // Recursive call with return
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
