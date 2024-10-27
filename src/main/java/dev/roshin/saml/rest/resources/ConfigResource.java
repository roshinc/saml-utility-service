package dev.roshin.saml.rest.resources;

import dev.roshin.saml.services.config.ConfigManager;
import dev.roshin.saml.services.config.records.ConfigData;
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
    private ConfigManager configManager;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public ConfigData getConfig() {
        return configManager.getConfigData();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/clearCache")
    public void clearConfigCache() {
        configManager.clearCache();
    }
}
