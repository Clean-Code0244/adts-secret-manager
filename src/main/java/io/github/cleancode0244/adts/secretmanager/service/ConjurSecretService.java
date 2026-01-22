package io.github.cleancode0244.adts.secretmanager.service;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Instant;

@Slf4j
public class ConjurSecretService {

    private final String applianceUrl;
    private final String account;
    private final String authnJwtServiceId;
    private final String sslCertificateContent;
    private final String tokenFilePath;

    private RestTemplate restTemplate;

    private String cachedAccessToken;
    private Instant tokenExpirationTime;

    public ConjurSecretService(String applianceUrl,
                               String account,
                               String authnJwtServiceId,
                               String sslCertificateContent,
                               String tokenFilePath) {
        this.applianceUrl = applianceUrl;
        this.account = account;
        this.authnJwtServiceId = authnJwtServiceId;
        this.sslCertificateContent = sslCertificateContent;
        this.tokenFilePath = tokenFilePath;
    }

    @PostConstruct
    public void init() {
        log.info("Initializing ConjurSecretService with Custom SSL & JWT...");
        validateConfig();

        try {
            // 1. SSL
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(
                    new ByteArrayInputStream(sslCertificateContent.getBytes(StandardCharsets.UTF_8))
            );

            // 2. Keystore
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null); // Empty keystore
            keyStore.setCertificateEntry("conjur-custom-cert", cert);

            // 3. TrustManager
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            // 4. SSL Context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            // 5. Request Factory
            SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                    if (connection instanceof HttpsURLConnection) {
                        ((HttpsURLConnection) connection).setSSLSocketFactory(sslContext.getSocketFactory());
                    }
                    super.prepareConnection(connection, httpMethod);
                }
            };

            // Timeout
            requestFactory.setConnectTimeout(5000);
            requestFactory.setReadTimeout(10000);

            this.restTemplate = new RestTemplate(requestFactory);
            log.info("Conjur RestTemplate initialized successfully with Custom SSL.");

        } catch (Exception e) {
            log.error("Failed to initialize Conjur SSL Context: {}", e.getMessage());
            throw new RuntimeException("Critical: Conjur SSL setup failed", e);
        }
    }

    public String getSecret(String variableId) {
        try {
            // 1. Get valid access token
            String accessToken = getOrRefreshAccessToken();

            // 2. Construct a url to get secret
            // Format: {url}/api/secrets/{account}/variable/{variableId}
            String url = String.format("%s/api/secrets/%s/variable/%s",
                    applianceUrl, account, variableId);

            HttpHeaders headers = new HttpHeaders();
            // Conjur Token format: Token token="base64_string"
            headers.set("Authorization", "Token token=\"" + accessToken + "\"");

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            return response.getBody();

        } catch (Exception e) {
            log.error("Failed to retrieve secret for key [{}]: {}", variableId, e.getMessage());
            throw new RuntimeException("Conjur Retrieve Secret Failed", e);
        }
    }

    /**
     * Getting Conjur Access Token via JWT Authentication.
     */
    private synchronized String getOrRefreshAccessToken() {
        if (cachedAccessToken != null && tokenExpirationTime != null && Instant.now().isBefore(tokenExpirationTime)) {
            return cachedAccessToken;
        }

        log.debug("Conjur Access Token is missing or expired. Authenticating via JWT...");

        try {
            String k8sJwtToken = Files.readString(Path.of(tokenFilePath)).trim();

            // Format: {url}/authn-jwt/{serviceId}/{account}/authenticate
            String authUrl = String.format("%s/authn-jwt/%s/%s/authenticate",
                    applianceUrl, authnJwtServiceId, account);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            headers.set("Accept-Encoding", "base64"); // Base64 kodlanmış yanıt istiyoruz

            // Body: "jwt=ey..."
            String body = "jwt=" + k8sJwtToken;
            HttpEntity<String> request = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(authUrl, request, String.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new IllegalStateException("Conjur Auth failed with status: " + response.getStatusCode());
            }

            this.cachedAccessToken = response.getBody();
            this.tokenExpirationTime = Instant.now().plusSeconds(480); // Default 8 minute caching

            log.info("Successfully authenticated to Conjur via JWT.");
            return cachedAccessToken;

        } catch (IOException e) {
            throw new RuntimeException("Could not read K8s Service Account Token from path: " + tokenFilePath, e);
        } catch (Exception e) {
            throw new RuntimeException("Conjur Authentication Failed", e);
        }
    }

    private void validateConfig() {
        if (!StringUtils.hasText(applianceUrl)) throw new IllegalArgumentException("CONJUR_APPLIANCE_URL is missing");
        if (!StringUtils.hasText(sslCertificateContent)) throw new IllegalArgumentException("CONJUR_SSL_CERTIFICATE is missing");
        if (!StringUtils.hasText(authnJwtServiceId)) throw new IllegalArgumentException("CONJUR_AUTHN_JWT_SERVICE_ID is missing");
    }
}