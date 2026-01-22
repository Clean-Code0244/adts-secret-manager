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
            // 1. URL
            @Value("${conjur.appliance-url}") String applianceUrl,

            // 2. Account
            @Value("${conjur.account}") String account,

            // 3. Service ID
            @Value("${conjur.authn-jwt-service-id}") String authnJwtServiceId,

            // 4. SSL Certificate
            @Value("${conjur.ssl-certificate}") String sslCertificate,

            // 5. Token File Path
            @Value("${conjur.authn-token-file}") String tokenFilePath
    ) {
        return new ConjurSecretService(
                applianceUrl,
                account,
                authnJwtServiceId,
                sslCertificate,
                tokenFilePath
        );
    }
}