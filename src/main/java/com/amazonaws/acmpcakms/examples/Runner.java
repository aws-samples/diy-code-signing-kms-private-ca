package com.amazonaws.acmpcakms.examples;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamilyRegistry;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import software.amazon.awssdk.services.acmpca.model.*;

public class Runner {

  private static final String DEFAULT_ALGORITHM_FAMILY = "RSA2048";
  private static final String DEFAULT_FILE_PATH =
      "target/diy-code-signing-kms-private-ca-1.0-SNAPSHOT.jar";
  private static final String ROOT_COMMON_NAME = "CodeSigningRoot";
  private static final String SUBORDINATE_COMMON_NAME = "CodeSigningSubordinate";
  private static final String END_ENTITY_COMMON_NAME = "CodeSigningCertificate";
  private static final String CMK_ALIAS = "CodeSigningCMK";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static String getSupportedAlgorithmsString() {
    return String.join(", ", AlgorithmFamilyRegistry.getSupportedFamilies());
  }

  public static void main(String[] args) throws Exception {

    // Parse command line arguments
    String filePath;
    String algorithmFamilyName;

    if (args.length == 0) {
      // Default case: use default file and algorithm
      filePath = DEFAULT_FILE_PATH;
      algorithmFamilyName = DEFAULT_ALGORITHM_FAMILY;
    } else if (args.length == 1 || args.length > 2) {
      // Invalid argument count: show usage
      System.err.println("Usage: java Runner [file_path algorithm]");
      System.err.println(
          "  file_path  - Path to the file to sign (default: " + DEFAULT_FILE_PATH + ")");
      System.err.println(
          "  algorithm  - Algorithm family to use (default: " + DEFAULT_ALGORITHM_FAMILY + ")");
      System.err.println();
      System.err.println("Examples:");
      System.err.println("  java Runner                                    # Use defaults");
      System.err.println(
          "  java Runner myfile.jar RSA2048                # Sign myfile.jar with RSA2048");
      System.err.println(
          "  java Runner /path/to/file.bin ECP256           # Sign file with ECP256");
      System.err.println(
          "  java Runner document.pdf MLDSA44              # Sign PDF with ML-DSA-44");
      System.err.println();
      System.err.println("Supported algorithms: " + getSupportedAlgorithmsString());
      return;
    } else {
      // Two arguments provided
      filePath = args[0];
      algorithmFamilyName = args[1];
    }

    // Validate and get algorithm family
    AlgorithmFamily algorithmFamily;
    try {
      algorithmFamily = AlgorithmFamilyRegistry.getFamily(algorithmFamilyName);
      System.out.println("Using algorithm family: " + algorithmFamily.getFamilyName());
      System.out.println("Using file: " + filePath);
    } catch (IllegalArgumentException e) {
      System.err.println("Error: " + e.getMessage());
      System.err.println("Supported algorithms: " + getSupportedAlgorithmsString());
      return;
    }

    // Read the file to be signed
    byte[] dataToSign;
    try {
      dataToSign = Files.readAllBytes(Paths.get(filePath));
      System.out.println("File size: " + dataToSign.length + " bytes");
    } catch (IOException e) {
      System.err.println("Error reading file '" + filePath + "': " + e.getMessage());
      return;
    }

    // Create algorithm-specific names to avoid collisions between different
    // algorithm families
    String algorithmSpecificRootName = ROOT_COMMON_NAME + "-" + algorithmFamily.getFamilyName();
    String algorithmSpecificSubordinateName =
        SUBORDINATE_COMMON_NAME + "-" + algorithmFamily.getFamilyName();
    String algorithmSpecificCmkAlias = CMK_ALIAS + "-" + algorithmFamily.getFamilyName();

    /*
     * Creating a CA hierarcy in AWS Private CA. This CA hiearchy consistant of a
     * Root and subordinate CA
     */
    System.out.println("Creating a CA hierarchy\n");

    PrivateCA rootPrivateCA =
        PrivateCA.builder()
            .withCommonName(algorithmSpecificRootName)
            .withType(CertificateAuthorityType.ROOT)
            .withAlgorithmFamily(algorithmFamily)
            .getOrCreate();

    PrivateCA subordinatePrivateCA =
        PrivateCA.builder()
            .withIssuer(rootPrivateCA)
            .withCommonName(algorithmSpecificSubordinateName)
            .withType(CertificateAuthorityType.SUBORDINATE)
            .withAlgorithmFamily(algorithmFamily)
            .getOrCreate();

    /* Creating a asymmetric key pair using AWS KMS */
    System.out.println();
    System.out.println("Creating a asymmetric key pair using AWS KMS\n");

    AsymmetricCMK codeSigningCMK =
        AsymmetricCMK.builder()
            .withAlias(algorithmSpecificCmkAlias)
            .withAlgorithmFamily(algorithmFamily)
            .getOrCreate();

    /* Creating a asymmetric key pair using AWS KMS */
    System.out.println();
    System.out.println(
        "Creating a CSR(Certificate signing request) for creating a code signing certificate\n");
    String codeSigningCSR = codeSigningCMK.generateCSR(END_ENTITY_COMMON_NAME);

    /* Issuing the code signing certificate from AWS Private CA */
    System.out.println();
    System.out.println("Issuing a code signing certificate from AWS Private CA\n");
    GetCertificateResponse codeSigningCertificate =
        subordinatePrivateCA.issueCodeSigningCertificate(codeSigningCSR);

    /* Creating a detached CMS code signing object */
    System.out.println();
    System.out.println("Creating a detached CMS code signing object\n");

    // Parse signer certificate from PEM
    X509CertificateHolder signerCert =
        CertificateUtils.fromPEM(codeSigningCertificate.certificate());

    Collection<X509CertificateHolder> chainCerts =
        CertificateUtils.toCertificateHolders(codeSigningCertificate.certificateChain());

    // Build certificate chain including signer cert and intermediate certs
    Collection<X509CertificateHolder> certChain = new ArrayList<>();
    certChain.add(signerCert);

    // Add intermediate certificates (excluding the signer cert itself)
    for (X509CertificateHolder chainCert : chainCerts) {
      if (!chainCert.equals(signerCert)) {
        certChain.add(chainCert);
      }
    }

    // Create detached CMS signature
    CMSCodeSigningObject cmsCodeSigningObject =
        CMSCodeSigningObject.createDetachedSignature(
            codeSigningCMK, algorithmFamily, dataToSign, signerCert, certChain);

    /* Save signature and root CA certificate to files */
    System.out.println();
    System.out.println("Saving detached signature and root CA certificate to files\n");

    // Save detached signature to .p7s file
    String signatureFileName = "signature-" + algorithmFamily.getFamilyName() + ".p7s";
    try (FileOutputStream sigOut = new FileOutputStream(signatureFileName)) {
      sigOut.write(cmsCodeSigningObject.toBytes());
    }
    System.out.println("Detached CMS signature saved to: " + signatureFileName);

    // Save Root CA certificate to PEM file
    String rootCAPEM = rootPrivateCA.getCertificate();
    String rootCAFileName = "root-ca-" + algorithmFamily.getFamilyName() + ".pem";
    try (FileOutputStream rootCAOut = new FileOutputStream(rootCAFileName)) {
      rootCAOut.write(rootCAPEM.getBytes(StandardCharsets.UTF_8));
    }
    System.out.println("Root CA certificate saved to: " + rootCAFileName);

    System.out.println("Detached signature created successfully\n");

    System.out.println();
    System.out.println(
        "Verifying the authenticity of the detached CMS signature and the integrity of the signed data\n");

    String rootCACertificatePEM =
        new String(Files.readAllBytes(Paths.get(rootCAFileName)), StandardCharsets.UTF_8);
    X509CertificateHolder rootCACertificate = CertificateUtils.fromPEM(rootCACertificatePEM);

    // Verify the detached CMS signature using the root CA loaded from file
    cmsCodeSigningObject.verifyDetachedSignature(dataToSign, rootCACertificate);

    // Demonstrate verification from files (simulating real-world usage)
    System.out.println();
    System.out.println("Demonstrating verification from separate files\n");

    // Read original data from the original file (not a copy)
    byte[] originalDataFromFile = Files.readAllBytes(Paths.get(filePath));

    // Read and parse CMS signature from .p7s file
    byte[] signatureFromFile = Files.readAllBytes(Paths.get(signatureFileName));
    CMSCodeSigningObject cmsFromFile = CMSCodeSigningObject.fromBytes(signatureFromFile);

    // Verify signature against original data
    cmsFromFile.verifyDetachedSignature(originalDataFromFile, rootCACertificate);

    System.out.println("Detached CMS signature verification successful!");
  }
}
