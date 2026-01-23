package io.github.cleancode0244.adts.secretmanager.service;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;

@Slf4j
public class ConjurSecretService {

    private final String applianceUrl;
    private final String account;
    private final String authnJwtServiceId;
    private final String sslCertificateContent;
    private final String tokenFilePath;
    private final boolean sslVerificationEnabled;

    private RestTemplate restTemplate;

    private String cachedAccessToken;
    private Instant tokenExpirationTime;

    public ConjurSecretService(String applianceUrl,
                               String account,
                               String authnJwtServiceId,
                               String sslCertificateContent,
                               String tokenFilePath,
                               boolean sslVerificationEnabled) {
        this.applianceUrl = applianceUrl;
        this.account = account;
        this.authnJwtServiceId = authnJwtServiceId;
        this.sslCertificateContent = sslCertificateContent;
        this.tokenFilePath = tokenFilePath;
        this.sslVerificationEnabled = sslVerificationEnabled;
    }

    @PostConstruct
    public void init() {
        log.info("Initializing ConjurSecretService with SSL Verification: {}", sslVerificationEnabled);
        validateConfig();

        try {
            SSLContext sslContext;

            if (sslVerificationEnabled) {
                log.info("SSL Verification is ENABLED. Using provided certificate.");
                sslContext = createSSLContextWithCertificate();
            } else {
                log.warn("SSL Verification is DISABLED. Trusting all certificates. (Not recommended for production!)");
                sslContext = createTrustAllSSLContext();
            }

            SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                    if (connection instanceof HttpsURLConnection) {
                        HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
                        httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());

                        if (!sslVerificationEnabled) {
                            httpsConnection.setHostnameVerifier((hostname, session) -> true);
                        }
                    }
                    super.prepareConnection(connection, httpMethod);
                }
            };

            requestFactory.setConnectTimeout(5000);
            requestFactory.setReadTimeout(10000);

            this.restTemplate = new RestTemplate(requestFactory);
            log.info("Conjur RestTemplate initialized successfully.");

        } catch (Exception e) {
            log.error("Failed to initialize Conjur SSL Context: {}", e.getMessage(), e);
            throw new RuntimeException("Critical: Conjur SSL setup failed", e);
        }
    }

    /**
     * Creates SSL Context with the provided certificate (SSL Verification Enabled)
     * Using the same configuration as the reference HttpClient implementation
     */
    private SSLContext createSSLContextWithCertificate() throws Exception {
        // 1. Certificate Factory
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(
                new ByteArrayInputStream(sslCertificateContent.getBytes(StandardCharsets.UTF_8))
        );

        // 2. KeyStore - Using JKS explicitly (same as reference implementation)
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("conjurTlsCaPath", cert);

        // 3. TrustManagerFactory - Using SunX509 explicitly (same as reference implementation)
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);

        // 4. SSL Context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        log.debug("SSL Context created with custom certificate using JKS KeyStore and SunX509 TrustManager");
        return sslContext;
    }

    /**
     * Creates SSL Context that trusts all certificates (SSL Verification Disabled)
     */
    private SSLContext createTrustAllSSLContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Trust all
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Trust all
                    }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());

        return sslContext;
    }

    public String getSecret(String variableId) {
        try {
            String accessToken = getOrRefreshAccessToken();

            // URL format matches reference implementation
            String url = String.format("%s/api/secrets/%s/variable/%s",
                    applianceUrl, account, variableId);

            HttpHeaders headers = new HttpHeaders();
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
            log.error("Failed to retrieve secret for key [{}]: {}", variableId, e.getMessage(), e);
            throw new RuntimeException("Conjur Retrieve Secret Failed", e);
        }
    }

    /**
     * Getting Conjur Access Token via JWT Authentication
     * Matches reference implementation's authentication flow
     */
    private synchronized String getOrRefreshAccessToken() {
        if (cachedAccessToken != null && tokenExpirationTime != null && Instant.now().isBefore(tokenExpirationTime)) {
            return cachedAccessToken;
        }

        log.debug("Conjur Access Token is missing or expired. Authenticating via JWT...");

        try {
            String k8sJwtToken = Files.readString(Path.of(tokenFilePath)).trim();

            // URL format matches reference implementation
            String authUrl = String.format("%s/authn-jwt/%s/%s/authenticate",
                    applianceUrl, authnJwtServiceId, account);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            headers.set("Accept-Encoding", "base64");

            String body = "jwt=" + k8sJwtToken;
            HttpEntity<String> request = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(authUrl, request, String.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new IllegalStateException("Conjur Auth failed with status: " + response.getStatusCode());
            }

            this.cachedAccessToken = response.getBody();
            this.tokenExpirationTime = Instant.now().plusSeconds(480);

            log.info("Successfully authenticated to Conjur via JWT.");
            return cachedAccessToken;

        } catch (IOException e) {
            throw new RuntimeException("Could not read K8s Service Account Token from path: " + tokenFilePath, e);
        } catch (Exception e) {
            throw new RuntimeException("Conjur Authentication Failed", e);
        }
    }

    private void validateConfig() {
        if (!StringUtils.hasText(applianceUrl)) {
            throw new IllegalArgumentException("CONJUR_APPLIANCE_URL is missing");
        }
        if (!StringUtils.hasText(authnJwtServiceId)) {
            throw new IllegalArgumentException("CONJUR_AUTHN_JWT_SERVICE_ID is missing");
        }
        if (!StringUtils.hasText(account)) {
            throw new IllegalArgumentException("CONJUR_ACCOUNT is missing");
        }
        if (!StringUtils.hasText(tokenFilePath)) {
            throw new IllegalArgumentException("CONJUR_AUTHN_TOKEN_FILE_PATH is missing");
        }

        if (sslVerificationEnabled && !StringUtils.hasText(sslCertificateContent)) {
            throw new IllegalArgumentException("CONJUR_SSL_CERTIFICATE is missing (required when SSL verification is enabled)");
        }
    }
}