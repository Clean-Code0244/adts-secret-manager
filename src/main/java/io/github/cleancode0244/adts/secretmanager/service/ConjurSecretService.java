package io.github.cleancode0244.adts.secretmanager.service;

import com.cyberark.conjur.api.Conjur;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;


import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class ConjurSecretService {

    private static final Logger log = LoggerFactory.getLogger(ConjurSecretService.class);

    private final String applianceUrl;
    private final String account;
    private final String authnLogin;
    private final String authnApiKey;

    private Conjur conjurClient;

    public ConjurSecretService(String applianceUrl, String account, String authnLogin, String authnApiKey) {
        this.applianceUrl = applianceUrl;
        this.account = account;
        this.authnLogin = authnLogin;
        this.authnApiKey = authnApiKey;
    }

    @PostConstruct
    public void init() {
        validateConfiguration();

        try {
            System.setProperty("CONJUR_APPLIANCE_URL", applianceUrl);
            System.setProperty("CONJUR_ACCOUNT", account);
            System.setProperty("CONJUR_AUTHN_LOGIN", authnLogin);
            System.setProperty("CONJUR_AUTHN_API_KEY", authnApiKey);

            // Trust-All SSL Strategy
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

            log.warn("Conjur SSL Verification DISABLED! (Trust-All Strategy Active)");

            this.conjurClient = new Conjur(sc);
            log.info("Conjur Client initialized. URL: {}", applianceUrl);

        } catch (Exception e) {
            log.error("Conjur Init Failed: {}", e.getMessage());
            throw new RuntimeException("Critical Error: Could not initialize Conjur Client", e);
        }
    }

    private void validateConfiguration() {
        List<String> missingFields = new ArrayList<>();
        if (!StringUtils.hasText(applianceUrl)) missingFields.add("conjur.appliance-url");
        if (!StringUtils.hasText(account)) missingFields.add("conjur.account");
        if (!StringUtils.hasText(authnLogin)) missingFields.add("conjur.authn-login");
        if (!StringUtils.hasText(authnApiKey)) missingFields.add("conjur.authn-api-key");

        if (!missingFields.isEmpty()) {
            throw new IllegalArgumentException("[ADTS-Lib] Missing config: " + missingFields);
        }
    }

    public String getSecret(String key) {
        return conjurClient.variables().retrieveSecret(key);
    }
}