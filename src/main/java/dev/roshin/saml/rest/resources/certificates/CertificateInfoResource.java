package dev.roshin.saml.rest.resources.certificates;

import com.google.gson.JsonObject;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/certificates")
@RequestScoped
public class CertificateInfoResource {
    private static final Logger logger = LoggerFactory.getLogger(CertificateInfoResource.class);

    @Inject
    private CertificateInfoService certificateInfoService;

    @GET
    @Path("/info")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCertificateInfo() {
        try {
            JsonObject certificateInfo = certificateInfoService.getAllCertificateInfo();
            return Response.ok(certificateInfo.toString()).build();
        } catch (Exception e) {
            logger.error("Error retrieving certificate information", e);
            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("error", "Failed to retrieve certificate information");
            errorResponse.addProperty("message", e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(errorResponse.toString())
                    .build();
        }
    }
}