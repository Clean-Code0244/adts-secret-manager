package io.github.cleancode0244.adts.secretmanager.config;

import io.github.cleancode0244.adts.secretmanager.service.ConjurSecretService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configuration for ADTS Secret Manager.
 * Activates only when 'app.secrets.provider' property is set to 'conjur'.
 */
@Configuration
public class SecretManagerAutoConfiguration {

    /**
     * Creates a ConjurSecretService bean if the condition is met.
     *
     * @param url Conjur URL
     * @param account Conjur Account
     * @param login Login ID
     * @param apiKey API Key
     * @return Configured ConjurSecretService instance
     */
    @Bean
    @ConditionalOnProperty(name = "app.secrets.provider", havingValue = "conjur")
    public ConjurSecretService conjurSecretService(
            @Value("${conjur.appliance-url:}") String url,
            @Value("${conjur.account:}") String account,
            @Value("${conjur.authn-login:}") String login,
            @Value("${conjur.authn-api-key:}") String apiKey
    ) {
        return new ConjurSecretService(url, account, login, apiKey);
    }
}