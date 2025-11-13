package com.amazonaws.acmpcakms.examples;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import java.util.*;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.services.acmpca.AcmPcaClient;
import software.amazon.awssdk.services.acmpca.model.*;
import software.amazon.awssdk.services.acmpca.waiters.AcmPcaWaiter;

public class PrivateCA {
  // Set up a PQ TLS HTTP client that will be used when connecting to AWS
  private static final SdkHttpClient AWS_CRT_HTTP_CLIENT =
      AwsCrtHttpClient.builder().postQuantumTlsEnabled(true).build();

  private final AcmPcaClient client;
  private final String commonName;
  private final CertificateAuthorityType type;
  private final AlgorithmFamily algorithmFamily;
  private final CertificateAuthority ca;
  private final String certificate;

  private PrivateCA(
      Optional<PrivateCA> issuerOption,
      String commonName,
      CertificateAuthorityType type,
      AlgorithmFamily algorithmFamily) {
    if (Objects.isNull(commonName) || commonName.isBlank()) {
      throw new IllegalArgumentException("A non-empty common name must be specified");
    }

    if (Objects.isNull(type)) {
      throw new IllegalArgumentException("A CA type must be specified");
    }

    if (Objects.isNull(algorithmFamily)) {
      throw new IllegalArgumentException("An algorithm family must be specified");
    }

    if (type.equals(CertificateAuthorityType.ROOT) && issuerOption.isPresent()) {
      throw new IllegalArgumentException("A root CA cannot have an issuer specified");
    }

    if (type.equals(CertificateAuthorityType.SUBORDINATE) && !issuerOption.isPresent()) {
      throw new IllegalArgumentException("A subordinate CA must have an issuer specified");
    }

    this.client = AcmPcaClient.builder().httpClient(AWS_CRT_HTTP_CLIENT).build();
    this.commonName = commonName;
    this.type = type;
    this.algorithmFamily = algorithmFamily;

    List<CertificateAuthority> discoveredCAs = listCAs();

    Optional<CertificateAuthority> matchingIssuerCAOption =
        issuerOption.flatMap(issuer -> discoveredCAs.stream().filter(issuer::matches).findFirst());

    if (issuerOption.isPresent() && !matchingIssuerCAOption.isPresent()) {
      throw new IllegalArgumentException("Could not find issuer matching " + issuerOption.get());
    }

    this.ca = discoveredCAs.stream().filter(this::matches).findFirst().orElseGet(this::createCA);

    System.out.println(
        "Using CA with CN=" + commonName + ": arn=" + ca.arn() + ", status=" + ca.status());

    if (ca.status().equals(CertificateAuthorityStatus.ACTIVE)) {
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

  private boolean matches(CertificateAuthority ca) {
    return type.equals(ca.type())
        && commonName.equals(ca.certificateAuthorityConfiguration().subject().commonName())
        && algorithmFamily
            .getPcaKeyAlgorithm()
            .equals(ca.certificateAuthorityConfiguration().keyAlgorithm())
        && algorithmFamily
            .getPcaSigningAlgorithm()
            .equals(ca.certificateAuthorityConfiguration().signingAlgorithm());
  }

  private CertificateAuthority createCA() {
    System.out.println("No matching CA found, creating a new one (" + this + ")");

    CreateCertificateAuthorityRequest createCARequest =
        CreateCertificateAuthorityRequest.builder()
            .tags(Tag.builder().key("Name").value(commonName).build())
            .idempotencyToken(UUID.randomUUID().toString())
            .certificateAuthorityType(type)
            .certificateAuthorityConfiguration(
                CertificateAuthorityConfiguration.builder()
                    .subject(ASN1Subject.builder().commonName(commonName).build())
                    .keyAlgorithm(algorithmFamily.getPcaKeyAlgorithm())
                    .signingAlgorithm(algorithmFamily.getPcaSigningAlgorithm())
                    .build())
            .build();

    CreateCertificateAuthorityResponse createCAResponse =
        client.createCertificateAuthority(createCARequest);
    String caArn = createCAResponse.certificateAuthorityArn();

    DescribeCertificateAuthorityRequest describeCARequest =
        DescribeCertificateAuthorityRequest.builder().certificateAuthorityArn(caArn).build();

    DescribeCertificateAuthorityResponse describeCAResponse =
        client.describeCertificateAuthority(describeCARequest);
    return describeCAResponse.certificateAuthority();
  }

  private String getCACertificate() {
    GetCertificateAuthorityCertificateRequest getCACertificateRequest =
        GetCertificateAuthorityCertificateRequest.builder()
            .certificateAuthorityArn(ca.arn())
            .build();

    GetCertificateAuthorityCertificateResponse getCACertificateResponse =
        client.getCertificateAuthorityCertificate(getCACertificateRequest);
    return getCACertificateResponse.certificate();
  }

  private List<CertificateAuthority> listCAs() {
    String nextToken = null;
    List<CertificateAuthority> discoveredCAs = new ArrayList<>();
    do {
      ListCertificateAuthoritiesRequest request =
          ListCertificateAuthoritiesRequest.builder().nextToken(nextToken).build();
      ListCertificateAuthoritiesResponse results = client.listCertificateAuthorities(request);

      discoveredCAs.addAll(
          results.certificateAuthorities().stream()
              .filter(ca -> ca.status().equals(CertificateAuthorityStatus.ACTIVE))
              .toList());
      nextToken = results.nextToken();
    } while (Objects.nonNull(nextToken));

    return discoveredCAs;
  }

  private String getCACSR() {
    System.out.println("Retrieving CA CertSigningRequest for arn=" + ca.arn());

    GetCertificateAuthorityCsrRequest getCACSRRequest =
        GetCertificateAuthorityCsrRequest.builder().certificateAuthorityArn(ca.arn()).build();

    AcmPcaWaiter waiter = client.waiter();
    waiter.waitUntilCertificateAuthorityCSRCreated(getCACSRRequest);

    GetCertificateAuthorityCsrResponse getCACSRResult =
        client.getCertificateAuthorityCsr(getCACSRRequest);
    String caCSR = getCACSRResult.csr();

    System.out.println(
        "Retrieved CA CertificateSigningRequest for arn="
            + ca.arn()
            + ", CertSigningRequest length: "
            + caCSR.getBytes().length
            + " bytes");

    return caCSR;
  }

  private GetCertificateResponse getCertificate(CertificateAuthority ca, String certificateArn) {
    System.out.println("Retrieving certificate for arn=" + certificateArn);

    GetCertificateRequest getCertificateRequest =
        GetCertificateRequest.builder()
            .certificateAuthorityArn(ca.arn())
            .certificateArn(certificateArn)
            .build();

    AcmPcaWaiter waiter = client.waiter();
    waiter.waitUntilCertificateIssued(getCertificateRequest);

    GetCertificateResponse result = client.getCertificate(getCertificateRequest);

    return result;
  }

  private String activateRootCA() {
    String caCSR = getCACSR();

    System.out.println("Activating Root CA certificate for arn=" + ca.arn());

    Validity validity = Validity.builder().type(ValidityPeriodType.YEARS).value(10L).build();

    IssueCertificateRequest issueCertificateRequest =
        IssueCertificateRequest.builder()
            .idempotencyToken(UUID.randomUUID().toString())
            .certificateAuthorityArn(ca.arn())
            .csr(SdkBytes.fromUtf8String(caCSR))
            .signingAlgorithm(algorithmFamily.getPcaSigningAlgorithm())
            .templateArn("arn:aws:acm-pca:::template/RootCACertificate/V1")
            .validity(validity)
            .build();

    IssueCertificateResponse issueCertificateResponse =
        client.issueCertificate(issueCertificateRequest);
    String caCertificateArn = issueCertificateResponse.certificateArn();

    GetCertificateResponse getCertificateResult = getCertificate(ca, caCertificateArn);

    System.out.println("Importing CA certificate for arn=" + ca.arn());

    ImportCertificateAuthorityCertificateRequest importCACertRequest =
        ImportCertificateAuthorityCertificateRequest.builder()
            .certificateAuthorityArn(ca.arn())
            .certificate(SdkBytes.fromUtf8String(getCertificateResult.certificate()))
            .build();

    client.importCertificateAuthorityCertificate(importCACertRequest);

    return getCertificateResult.certificate();
  }

  private String activateSubordinateCA(CertificateAuthority issuingCA) {
    String caCSR = getCACSR();

    System.out.println("Activating Subordinate CA certificate for arn=" + ca.arn());

    Validity validity = Validity.builder().type(ValidityPeriodType.YEARS).value(5L).build();

    IssueCertificateRequest issueCertificateRequest =
        IssueCertificateRequest.builder()
            .idempotencyToken(UUID.randomUUID().toString())
            .certificateAuthorityArn(issuingCA.arn())
            .csr(SdkBytes.fromUtf8String(caCSR))
            .signingAlgorithm(algorithmFamily.getPcaSigningAlgorithm())
            .templateArn("arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1")
            .validity(validity)
            .build();

    IssueCertificateResponse issueCertificateResponse =
        client.issueCertificate(issueCertificateRequest);
    String caCertificateArn = issueCertificateResponse.certificateArn();

    GetCertificateResponse getCertificateResult = getCertificate(issuingCA, caCertificateArn);

    System.out.println("Importing CA certificate for arn=" + ca.arn());

    ImportCertificateAuthorityCertificateRequest importCACertRequest =
        ImportCertificateAuthorityCertificateRequest.builder()
            .certificateAuthorityArn(ca.arn())
            .certificateChain(SdkBytes.fromUtf8String(getCertificateResult.certificateChain()))
            .certificate(SdkBytes.fromUtf8String(getCertificateResult.certificate()))
            .build();

    client.importCertificateAuthorityCertificate(importCACertRequest);

    return getCertificateResult.certificate();
  }

  public GetCertificateResponse issueCodeSigningCertificate(String csr) {
    System.out.println(
        "Issuing Leaf Code Signing Certificate. Submitting CertificateSigningRequest PEM to ACM to be signed by "
            + algorithmFamily.getFamilyName()
            + " CA arn="
            + ca.arn());

    Validity validity = Validity.builder().type(ValidityPeriodType.YEARS).value(1L).build();

    IssueCertificateRequest issueCertificateRequest =
        IssueCertificateRequest.builder()
            .idempotencyToken(UUID.randomUUID().toString())
            .certificateAuthorityArn(ca.arn())
            .csr(SdkBytes.fromUtf8String(csr))
            .signingAlgorithm(algorithmFamily.getPcaSigningAlgorithm())
            .templateArn("arn:aws:acm-pca:::template/CodeSigningCertificate/V1")
            .validity(validity)
            .build();

    IssueCertificateResponse issueCertificateResponse =
        client.issueCertificate(issueCertificateRequest);
    String certificateArn = issueCertificateResponse.certificateArn();

    GetCertificateRequest getCertificateRequest =
        GetCertificateRequest.builder()
            .certificateAuthorityArn(ca.arn())
            .certificateArn(certificateArn)
            .build();

    AcmPcaWaiter waiter = client.waiter();
    waiter.waitUntilCertificateIssued(getCertificateRequest);

    GetCertificateResponse result = client.getCertificate(getCertificateRequest);

    System.out.println("ACM generated leaf code signing certificate: " + certificateArn);

    return result;
  }

  @Override
  public String toString() {
    return "PrivateCA{" + "commonName='" + commonName + '\'' + ", type=" + type + '}';
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private PrivateCA issuer;
    private String commonName;
    private CertificateAuthorityType type;
    private AlgorithmFamily algorithmFamily;

    private Builder() {}

    public Builder withIssuer(PrivateCA issuer) {
      this.issuer = issuer;
      return this;
    }

    public Builder withCommonName(String commonName) {
      this.commonName = commonName;
      return this;
    }

    public Builder withType(CertificateAuthorityType type) {
      this.type = type;
      return this;
    }

    public Builder withAlgorithmFamily(AlgorithmFamily algorithmFamily) {
      this.algorithmFamily = algorithmFamily;
      return this;
    }

    public PrivateCA getOrCreate() {
      return new PrivateCA(Optional.ofNullable(issuer), commonName, type, algorithmFamily);
    }
  }
}
