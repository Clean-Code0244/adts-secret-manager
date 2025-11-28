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

/**
 * Service implementation for CyberArk Conjur integration.
 * <p>
 * This service initializes the Conjur client with a Trust-All SSL strategy
 * to facilitate connections in environments with self-signed certificates.
 * </p>
 */
public class ConjurSecretService {

    private static final Logger log = LoggerFactory.getLogger(ConjurSecretService.class);

    private final String applianceUrl;
    private final String account;
    private final String authnLogin;
    private final String authnApiKey;

    private Conjur conjurClient;

    /**
     * Constructor for dependency injection via AutoConfiguration.
     *
     * @param applianceUrl Conjur Appliance URL
     * @param account Conjur Account Name
     * @param authnLogin Login ID (host/...)
     * @param authnApiKey API Key for the host
     */
    public ConjurSecretService(String applianceUrl, String account, String authnLogin, String authnApiKey) {
        this.applianceUrl = applianceUrl;
        this.account = account;
        this.authnLogin = authnLogin;
        this.authnApiKey = authnApiKey;
    }

    /**
     * Initializes the Conjur client with system properties and SSL context.
     */
    @PostConstruct
    public void init() {
        validateConfiguration();

        try {
            System.setProperty("CONJUR_APPLIANCE_URL", applianceUrl);
            System.setProperty("CONJUR_ACCOUNT", account);
            System.setProperty("CONJUR_AUTHN_LOGIN", authnLogin);
            System.setProperty("CONJUR_AUTHN_API_KEY", authnApiKey);

            // 3. SSL Settings (Trust-All Strategy)
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

            log.warn("[ADTS-Lib] Conjur SSL Verification DISABLED! (Trust-All Strategy Active)");

            this.conjurClient = new Conjur(sc);

            log.info("[ADTS-Lib] Conjur Client initialized successfully.");
            log.info("   - URL: {}", applianceUrl);
            log.info("   - Account: {}", account);
            log.info("   - Login: {}", authnLogin);

        } catch (Exception e) {
            log.error("[ADTS-Lib] Conjur Init Failed: {}", e.getMessage());
            throw new RuntimeException("Critical Error: Could not initialize Conjur Client in Library", e);
        }
    }

    private void validateConfiguration() {
        List<String> missingFields = new ArrayList<>();
        if (!StringUtils.hasText(applianceUrl)) missingFields.add("conjur.appliance-url");
        if (!StringUtils.hasText(account)) missingFields.add("conjur.account");
        if (!StringUtils.hasText(authnLogin)) missingFields.add("conjur.authn-login");
        if (!StringUtils.hasText(authnApiKey)) missingFields.add("conjur.authn-api-key");

        if (!missingFields.isEmpty()) {
            String msg = String.format("[ADTS-Lib] Missing Conjur configuration: %s", missingFields);
            log.error("{}", msg);
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Retrieves a secret from Conjur vault.
     *
     * @param key The variable ID (e.g., db/password)
     * @return The secret value in plain text
     */
    public String getSecret(String key) {
        return conjurClient.variables().retrieveSecret(key);
    }
}