package dev.roshin.saml.services.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

import java.time.Clock;

@ApplicationScoped
public class ClockProducer {

    @Produces
    public Clock produceClock() {
        return Clock.systemDefaultZone();
    }
}
