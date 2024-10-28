package dev.roshin.saml.util.problem;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
@ApplicationScoped
public class GeneralExceptionMapper implements ExceptionMapper<Throwable> {

    @Inject
    private UriInfo uriInfo;

    @Override
    public Response toResponse(Throwable exception) {
        int status = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
        String type = exception.getClass().getSimpleName();
        String title = exception.getCause() != null ? exception.getCause().getMessage() : exception.getMessage();
        String detail = exception.getMessage();
        String instance = uriInfo.getRequestUri().toString();

        ProblemDetails problem = new ProblemDetails(type, title, status, detail, instance);

        return Response.status(status)
                .entity(problem)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
