package io.github.cleancode0244.adts.secretmanager.config;

import io.github.cleancode0244.adts.secretmanager.service.ConjurSecretService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;

@Configuration
@Conditional(ConjurEnabledCondition.class)
public class ConjurLibraryConfiguration {

    @Bean
    public ConjurSecretService conjurSecretService(
            @Value("${conjur.appliance-url:}") String url,
            @Value("${conjur.account:}") String account,
            @Value("${conjur.authn-login:}") String login,
            @Value("${conjur.authn-api-key:}") String apiKey
    ) {
        return new ConjurSecretService(url, account, login, apiKey);
    }
}