package dev.roshin.saml.rest.resources;


import dev.roshin.saml.processing.SamlProcessor;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/saml")
@RequestScoped
public class SamlAssertionService {

    @Inject
    private SamlProcessor samlProcessor;  // Assuming a SAML processing class exists to handle logic

    @POST
    @Path("/generate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateAccountAssertion(@QueryParam("jsonRequest") String jsonRequest,
                                             @QueryParam("providerId") String providerId) {
        try {
            String samlAssertion = samlProcessor.generateSamlAssertion(jsonRequest, providerId);
            return Response.ok(samlAssertion).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error generating SAML assertion: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("/generateWithToken")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateAccountAssertionWithToken(@QueryParam("jsonRequest") String jsonRequest,
                                                      @QueryParam("sessionToken") String sessionToken,
                                                      @QueryParam("providerId") String providerId) {
        try {
            String samlAssertion = samlProcessor.generateSamlAssertionWithToken(jsonRequest, sessionToken, providerId);
            return Response.ok(samlAssertion).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error generating SAML assertion with token: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("/parse")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response parseAccountAssertion(@QueryParam("providerId") String providerId,
                                          @QueryParam("SAMLResponse") String samlResponse) {
        try {
            JsonObject parsedResponse = samlProcessor.parseSamlAssertion(samlResponse, providerId);
            return Response.ok(parsedResponse).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error parsing SAML assertion: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("/parse/parseByProvider")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response parseAccountAssertionByProvider(String authReqDataString) {
        try {
            JsonObject parsedResponse = samlProcessor.parseSamlAssertionByProvider(authReqDataString);
            return Response.ok(parsedResponse).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error parsing SAML assertion by provider: " + e.getMessage()).build();
        }
    }
}
