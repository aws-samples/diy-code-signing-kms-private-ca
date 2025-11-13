package com.amazonaws.acmpcakms.examples;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import java.io.IOException;
import java.io.StringWriter;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class CMSCodeSigningObject {

  private final CMSSignedData cmsSignedData;

  public CMSCodeSigningObject(CMSSignedData cmsSignedData) {
    this.cmsSignedData = Objects.requireNonNull(cmsSignedData, "CMS SignedData must not be null");
  }

  public static CMSCodeSigningObject fromBytes(byte[] cmsBytes) throws CMSException {
    if (cmsBytes == null) {
      throw new IllegalArgumentException("CMS bytes must not be null");
    }

    CMSSignedData signedData = new CMSSignedData(cmsBytes);
    return new CMSCodeSigningObject(signedData);
  }

  public static CMSCodeSigningObject fromPEM(String pemData) throws Exception {
    if (pemData == null || pemData.trim().isEmpty()) {
      throw new IllegalArgumentException("PEM data must not be null or empty");
    }

    // Extract base64 content from PEM
    String base64Content =
        pemData
            .replaceAll("-----BEGIN [^-]+-----", "")
            .replaceAll("-----END [^-]+-----", "")
            .replaceAll("\\s", "");

    byte[] cmsBytes = Base64.getDecoder().decode(base64Content);
    return fromBytes(cmsBytes);
  }

  public static String getSubjectName(X509Certificate certificate) {
    return certificate.getSubjectDN().getName();
  }

  public static CMSCodeSigningObject createDetachedSignature(
      AsymmetricCMK cmk,
      AlgorithmFamily algorithmFamily,
      byte[] dataToSign,
      X509CertificateHolder signerCert,
      Collection<X509CertificateHolder> certChain)
      throws Exception {

    if (cmk == null) {
      throw new IllegalArgumentException("AsymmetricCMK must not be null");
    }
    if (algorithmFamily == null) {
      throw new IllegalArgumentException("AlgorithmFamily must not be null");
    }
    if (dataToSign == null) {
      throw new IllegalArgumentException("Data to sign must not be null");
    }
    if (signerCert == null) {
      throw new IllegalArgumentException("Signer certificate must not be null");
    }
    if (certChain == null || certChain.isEmpty()) {
      throw new IllegalArgumentException("Certificate chain must not be null or empty");
    }

    // Create CMS generator for detached signatures
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

    // Add certificates to the CMS structure
    List<X509CertificateHolder> certificates = new ArrayList<>(certChain);
    Store<X509CertificateHolder> certStore = new CollectionStore<>(certificates);
    generator.addCertificates(certStore);

    // Get content signer from Signing class
    System.out.println(
        "Creating a BouncyCastle ContentSigner which will call out to KMS for signing operations.");
    ContentSigner contentSigner = Signing.createContentSigner(cmk, algorithmFamily);

    // Create signer info generator with authenticated attributes
    JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder =
        new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build());
    SignerInfoGenerator signerInfoGenerator =
        signerInfoGeneratorBuilder.build(contentSigner, signerCert);

    generator.addSignerInfoGenerator(signerInfoGenerator);

    // Generate detached signature (data is not included in the CMS structure)
    CMSTypedData content = new CMSProcessableByteArray(dataToSign);
    CMSSignedData signedData = generator.generate(content, false); // false = detached signature

    System.out.println(
        "Successfully created detached " + algorithmFamily.getFamilyName() + " signature.");

    return new CMSCodeSigningObject(signedData);
  }

  public void verifyDetachedSignature(byte[] originalData, X509CertificateHolder rootCertificate)
      throws Exception {
    validateInputs(originalData, rootCertificate);

    System.out.println("Verifying detached signature using standard PKIX validation");

    Set<TrustAnchor> trustAnchors = createTrustAnchors(rootCertificate);
    CertStore pkixCertStore = createCertStore();
    SignerInformation signer = getSingleSigner();
    X509CertificateHolder signerCertHolder = getSignerCertificate(signer);

    validateCertificatePath(trustAnchors, pkixCertStore, signerCertHolder);
    verifySignature(originalData, signerCertHolder);
  }

  private void validateInputs(byte[] originalData, X509CertificateHolder rootCertificate) {
    if (originalData == null) {
      throw new IllegalArgumentException("Original data must not be null");
    }
    if (rootCertificate == null) {
      throw new IllegalArgumentException("Root certificate must not be null");
    }
  }

  private Set<TrustAnchor> createTrustAnchors(X509CertificateHolder rootCertificate)
      throws Exception {
    X509Certificate rootCert = CertificateUtils.toCertificate(rootCertificate);
    Set<TrustAnchor> trustAnchors = new HashSet<>();
    trustAnchors.add(new TrustAnchor(rootCert, null));
    return trustAnchors;
  }

  private CertStore createCertStore() throws Exception {
    Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
    Collection<X509CertificateHolder> cmsEmbeddedCerts = certStore.getMatches(null);

    if (cmsEmbeddedCerts.isEmpty()) {
      throw new SignatureException("No certificates found in detached signature.");
    }

    Set<X509Certificate> intermediateCerts = new HashSet<>();
    for (X509CertificateHolder certHolder : cmsEmbeddedCerts) {
      intermediateCerts.add(CertificateUtils.toCertificate(certHolder));
    }

    CollectionCertStoreParameters certStoreParams =
        new CollectionCertStoreParameters(intermediateCerts);
    return CertStore.getInstance("Collection", certStoreParams, BouncyCastleProvider.PROVIDER_NAME);
  }

  private SignerInformation getSingleSigner() throws SignatureException {
    SignerInformationStore signers = cmsSignedData.getSignerInfos();

    if (signers.size() != 1) {
      throw new SignatureException("Expected exactly one signer, found: " + signers.size());
    }

    return signers.getSigners().iterator().next();
  }

  private X509CertificateHolder getSignerCertificate(SignerInformation signer) throws Exception {
    Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
    Collection<X509CertificateHolder> matches = certStore.getMatches(signer.getSID());

    if (matches.isEmpty()) {
      throw new SignatureException("Signer certificate not found in detached signature.");
    }

    return matches.iterator().next();
  }

  private void validateCertificatePath(
      Set<TrustAnchor> trustAnchors,
      CertStore pkixCertStore,
      X509CertificateHolder signerCertHolder)
      throws Exception {
    X509Certificate signerCert = CertificateUtils.toCertificate(signerCertHolder);

    X509CertSelector selector = new X509CertSelector();
    selector.setCertificate(signerCert);

    PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
    pkixParams.addCertStore(pkixCertStore);
    pkixParams.setRevocationEnabled(false);

    CertPathBuilder pathBuilder =
        CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
    CertPathBuilderResult result = pathBuilder.build(pkixParams);
    String certPath =
        String.join(
            ", ",
            result.getCertPath().getCertificates().stream()
                .map(cert -> getSubjectName((X509Certificate) cert))
                .toList());

    System.out.println(
        "Certificate path to trusted Root CA found. Path is {"
            + certPath
            + "}. Certificate Chain verified by BouncyCastle.");
  }

  private void verifySignature(byte[] originalData, X509CertificateHolder signerCertHolder)
      throws Exception {
    SignerInformationVerifier verifier =
        new JcaSignerInfoVerifierBuilder(
                new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build())
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(signerCertHolder);

    CMSTypedData content = new CMSProcessableByteArray(originalData);
    CMSSignedData signedDataWithContent = new CMSSignedData(content, cmsSignedData.getEncoded());

    SignerInformationStore newSigners = signedDataWithContent.getSignerInfos();
    SignerInformation newSigner = newSigners.getSigners().iterator().next();

    if (!newSigner.verify(verifier)) {
      throw new SignatureException("Detached signature verification failed");
    } else {
      System.out.println("Leaf signature verified by BouncyCastle.");
    }
  }

  public byte[] toBytes() throws IOException {
    return cmsSignedData.getEncoded();
  }

  public String toPEM() throws IOException {
    byte[] cmsBytes = toBytes();

    StringWriter stringWriter = new StringWriter();
    try (PemWriter pemWriter = new PemWriter(stringWriter)) {
      PemObject pemObject = new PemObject("PKCS7", cmsBytes);
      pemWriter.writeObject(pemObject);
    }

    String pem = stringWriter.toString();
    System.out.println(
        "Generated detached signature in PEM format, length:\n" + pem.getBytes().length + " bytes");

    return pem;
  }

  public CMSSignedData getCMSSignedData() {
    return cmsSignedData;
  }

  public Collection<X509CertificateHolder> getEmbeddedCertificates() {
    Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
    return certStore.getMatches(null);
  }

  public Collection<SignerInformation> getSigners() {
    return cmsSignedData.getSignerInfos().getSigners();
  }
}
