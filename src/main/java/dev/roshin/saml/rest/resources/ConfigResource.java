package dev.roshin.saml.rest.resources;

import dev.roshin.saml.services.config.ConfigService;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/config")
@RequestScoped
public class ConfigResource {

    @Inject
    private ConfigService configService;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public ConfigService.ConfigData getConfig() {
        return configService.getConfigData();
    }
}
