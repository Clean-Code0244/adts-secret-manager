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
            @Value("${conjur.appliance-url}") String applianceUrl,
            @Value("${conjur.account}") String account,
            @Value("${conjur.authn-jwt-service-id}") String authnJwtServiceId,
            @Value("${conjur.ssl-certificate:#{null}}") String sslCertificate,
            @Value("${conjur.authn-token-file-path}") String tokenFilePath,
            @Value("${conjur.ssl-verification-enabled:true}") boolean sslVerificationEnabled
    ) {
        return new ConjurSecretService(
                applianceUrl,
                account,
                authnJwtServiceId,
                sslCertificate,
                tokenFilePath,
                sslVerificationEnabled
        );
    }
}