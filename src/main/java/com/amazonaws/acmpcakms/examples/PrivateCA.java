package com.amazonaws.acmpcakms.examples;


import com.amazonaws.regions.Regions;
import com.amazonaws.services.acmpca.AWSACMPCA;
import com.amazonaws.services.acmpca.AWSACMPCAClientBuilder;
import com.amazonaws.services.acmpca.model.*;
import com.amazonaws.waiters.Waiter;
import com.amazonaws.waiters.WaiterParameters;

import java.nio.ByteBuffer;
import java.util.*;

public class PrivateCA {

    private final AWSACMPCA client;
    private final String commonName;
    private final CertificateAuthorityType type;
    private final CertificateAuthority ca;
    private final String certificate;

    private PrivateCA(final Optional<PrivateCA> issuerOption, final String commonName, final CertificateAuthorityType type) {
        if (Objects.isNull(commonName) || commonName.isBlank()) {
            throw new IllegalArgumentException("A non-empty common name must be specified");
        }

        if (Objects.isNull(type)) {
            throw new IllegalArgumentException("A CA type must be specified");
        }

        if (type.equals(CertificateAuthorityType.ROOT) && issuerOption.isPresent()) {
            throw new IllegalArgumentException("A root CA cannot have an issuer specified");
        }

        if (type.equals(CertificateAuthorityType.SUBORDINATE) && !issuerOption.isPresent()) {
            throw new IllegalArgumentException("A subordinate CA must have an issuer specified");
        }

        this.client = AWSACMPCAClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        this.commonName = commonName;
        this.type = type;

        List<CertificateAuthority> discoveredCAs = listCAs();

        Optional<CertificateAuthority> matchingIssuerCAOption = issuerOption.flatMap(issuer -> discoveredCAs.stream()
                .filter(issuer::matches)
                .findFirst());

        if (issuerOption.isPresent() && !matchingIssuerCAOption.isPresent()) {
            throw new IllegalArgumentException("Could not find issuer matching " + issuerOption.get());
        }

        this.ca = discoveredCAs.stream()
                .filter(this::matches)
                .findFirst()
                .orElseGet(this::createCA);

        System.out.println("Got CA with CN="  + commonName + ": arn=" + ca.getArn() + ", status=" + ca.getStatus());

        if (ca.getStatus().equals(CertificateAuthorityStatus.ACTIVE.toString())) {
            certificate = getCACertificate();
           return;
        }

        if (type == CertificateAuthorityType.ROOT) {
            this.certificate = activateRootCA();
        } else {
            this.certificate = activateSubordinateCA(matchingIssuerCAOption.get());
        }
    }

    public String getCertificate() {
        return certificate;
    }

    private boolean matches(final CertificateAuthority ca) {
        return type.toString().equals(ca.getType()) &&
                commonName.equals(ca.getCertificateAuthorityConfiguration().getSubject().getCommonName());
    }

    private CertificateAuthority createCA() {
        System.out.println("No matching CA found, creating a new one (" + this + ")");

        CreateCertificateAuthorityRequest createCARequest = new CreateCertificateAuthorityRequest()
                .withTags(new Tag()
                        .withKey("Name")
                        .withValue(commonName))
                .withIdempotencyToken(UUID.randomUUID().toString())
                .withCertificateAuthorityType(type)
                .withCertificateAuthorityConfiguration(new CertificateAuthorityConfiguration()
                        .withSubject(new ASN1Subject()
                                .withCommonName(commonName))
                        .withKeyAlgorithm(KeyAlgorithm.RSA_2048)
                        .withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA));

       String caArn = client.createCertificateAuthority(createCARequest).getCertificateAuthorityArn();

       DescribeCertificateAuthorityRequest describeCARequest = new DescribeCertificateAuthorityRequest()
               .withCertificateAuthorityArn(caArn);

       return client.describeCertificateAuthority(describeCARequest).getCertificateAuthority();
    }

    private String getCACertificate() {
        GetCertificateAuthorityCertificateRequest getCACertificateRequest = new GetCertificateAuthorityCertificateRequest()
                .withCertificateAuthorityArn(ca.getArn());

        return client.getCertificateAuthorityCertificate(getCACertificateRequest).getCertificate();
    }

    private List<CertificateAuthority> listCAs() {
        String nextToken = null;
        List<CertificateAuthority> discoveredCAs = new ArrayList<>();
        do {
            ListCertificateAuthoritiesResult results = client.listCertificateAuthorities(new ListCertificateAuthoritiesRequest()
                    .withNextToken(nextToken));

            discoveredCAs.addAll(results.getCertificateAuthorities());
            nextToken = results.getNextToken();
        } while (Objects.nonNull(nextToken));

        return discoveredCAs;
    }

    private String getCACSR() {
        System.out.println("Retrieving CA CSR for arn=" + ca.getArn());

        GetCertificateAuthorityCsrRequest getCACSRRequest = new GetCertificateAuthorityCsrRequest()
                .withCertificateAuthorityArn(ca.getArn());

        Waiter<GetCertificateAuthorityCsrRequest> waiter = client.waiters().certificateAuthorityCSRCreated();
        WaiterParameters<GetCertificateAuthorityCsrRequest> waiterParameters = new WaiterParameters<>(getCACSRRequest);
        waiter.run(waiterParameters);

        GetCertificateAuthorityCsrResult getCACSRResult = client.getCertificateAuthorityCsr(getCACSRRequest);
        String caCSR =  getCACSRResult.getCsr();

        System.out.println("CA CSR for arn=" + ca.getArn() + ":\n" + caCSR);

        return caCSR;
    }

    private GetCertificateResult getCertificate(final CertificateAuthority ca, final String certificateArn) {
        System.out.println("Retrieving certificate for arn=" + certificateArn);

        GetCertificateRequest getCertificateRequest = new GetCertificateRequest()
                .withCertificateAuthorityArn(ca.getArn())
                .withCertificateArn(certificateArn);

        Waiter<GetCertificateRequest> waiter = client.waiters().certificateIssued();
        WaiterParameters<GetCertificateRequest> waiterParameters = new WaiterParameters<>(getCertificateRequest);
        waiter.run(waiterParameters);

        GetCertificateResult result = client.getCertificate(getCertificateRequest);

        System.out.println("Certificate for arn=" + certificateArn + ":\n" + result.getCertificateChain() + "\n" + result.getCertificate());

        return result;
    }

    private String activateRootCA() {
        String caCSR = getCACSR();

        System.out.println("Issuing CA certificate for for arn=" + ca.getArn());

        Validity validity = new Validity()
                .withType(ValidityPeriodType.YEARS)
                .withValue(10L);

        IssueCertificateRequest issueCertificateRequest = new IssueCertificateRequest()
                .withIdempotencyToken(UUID.randomUUID().toString())
                .withCertificateAuthorityArn(ca.getArn())
                .withCsr(ByteBuffer.wrap(caCSR.getBytes()))
                .withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA)
                .withTemplateArn("arn:aws:acm-pca:::template/RootCACertificate/V1")
                .withValidity(validity);

        String caCertificateArn = client.issueCertificate(issueCertificateRequest).getCertificateArn();

        GetCertificateResult getCertificateResult = getCertificate(ca, caCertificateArn);

        System.out.println("Importing CA certificate for for arn=" + ca.getArn());

        ImportCertificateAuthorityCertificateRequest importCACertRequest = new ImportCertificateAuthorityCertificateRequest()
                .withCertificateAuthorityArn(ca.getArn())
                .withCertificate(ByteBuffer.wrap(getCertificateResult.getCertificate().getBytes()));

        client.importCertificateAuthorityCertificate(importCACertRequest);

        return getCertificateResult.getCertificate();
    }

    private String activateSubordinateCA(final CertificateAuthority issuingCA) {
        String caCSR = getCACSR();

        System.out.println("Issuing CA certificate for for arn=" + ca.getArn());

        Validity validity = new Validity()
                .withType(ValidityPeriodType.YEARS)
                .withValue(5L);

        IssueCertificateRequest issueCertificateRequest = new IssueCertificateRequest()
                .withIdempotencyToken(UUID.randomUUID().toString())
                .withCertificateAuthorityArn(issuingCA.getArn())
                .withCsr(ByteBuffer.wrap(caCSR.getBytes()))
                .withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA)
                .withTemplateArn("arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1")
                .withValidity(validity);

        String caCertificateArn = client.issueCertificate(issueCertificateRequest).getCertificateArn();

        GetCertificateResult getCertificateResult = getCertificate(issuingCA, caCertificateArn);

        System.out.println("Importing CA certificate for for arn=" + ca.getArn());

        ImportCertificateAuthorityCertificateRequest importCACertRequest = new ImportCertificateAuthorityCertificateRequest()
                .withCertificateAuthorityArn(ca.getArn())
                .withCertificateChain(ByteBuffer.wrap(getCertificateResult.getCertificateChain().getBytes()))
                .withCertificate(ByteBuffer.wrap(getCertificateResult.getCertificate().getBytes()));

        client.importCertificateAuthorityCertificate(importCACertRequest);

        return getCertificateResult.getCertificate();
    }

    public GetCertificateResult issueCodeSigningCertificate(final String csr) {
        System.out.println("Issuing code signing certificate for for arn=" + ca.getArn());

        Validity validity = new Validity()
                .withType(ValidityPeriodType.YEARS)
                .withValue(1L);

        IssueCertificateRequest issueCertificateRequest = new IssueCertificateRequest()
                .withIdempotencyToken(UUID.randomUUID().toString())
                .withCertificateAuthorityArn(ca.getArn())
                .withCsr(ByteBuffer.wrap(csr.getBytes()))
                .withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA)
                .withTemplateArn("arn:aws:acm-pca:::template/CodeSigningCertificate/V1")
                .withValidity(validity);

       String certificateArn = client.issueCertificate(issueCertificateRequest).getCertificateArn();

        GetCertificateRequest getCertificateRequest = new GetCertificateRequest()
                .withCertificateAuthorityArn(ca.getArn())
                .withCertificateArn(certificateArn);

        Waiter<GetCertificateRequest> waiter = client.waiters().certificateIssued();
        WaiterParameters<GetCertificateRequest> waiterParameters = new WaiterParameters<>(getCertificateRequest);
        waiter.run(waiterParameters);

        GetCertificateResult result = client.getCertificate(getCertificateRequest);

        System.out.println("Generated code signing certificate:\n" + result.getCertificate());

        return result;
    }

    @Override
    public String toString() {
        return "PrivateCA{" +
                "commonName='" + commonName + '\'' +
                ", type=" + type +
                '}';
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private PrivateCA issuer;
        private String commonName;
        private CertificateAuthorityType type;

        private Builder() {}

        public Builder withIssuer(final PrivateCA issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder withCommonName(final String commonName) {
            this.commonName = commonName;
            return this;
        }

        public Builder withType(final CertificateAuthorityType type) {
            this.type = type;
            return this;
        }

        public PrivateCA getOrCreate() {
            return new PrivateCA(Optional.ofNullable(issuer), commonName, type);
        }
    }
}
