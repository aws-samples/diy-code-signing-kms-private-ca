package com.amazonaws.acmpcakms.examples;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

public class AsymmetricCMK {

  private final KmsClient client;
  private final String alias;
  private final String keyId;
  private final AlgorithmFamily algorithmFamily;

  private AsymmetricCMK(String alias, AlgorithmFamily algorithmFamily) {
    if (Objects.isNull(alias) || alias.isBlank()) {
      throw new IllegalArgumentException("A non-empty alias must be specified");
    }
    if (Objects.isNull(algorithmFamily)) {
      throw new IllegalArgumentException("An algorithm family must be specified");
    }

    // Set up a PQ TLS HTTP client that will be used when connecting to AWS
    SdkHttpClient awsCrtHttpClient = AwsCrtHttpClient.builder().postQuantumTlsEnabled(true).build();

    this.client = KmsClient.builder().httpClient(awsCrtHttpClient).build();
    this.alias = alias;
    this.algorithmFamily = algorithmFamily;

    List<AliasListEntry> discoveredAliases = listAliases();

    this.keyId =
        discoveredAliases.stream()
            .filter(this::matches)
            .map(AliasListEntry::targetKeyId)
            .findFirst()
            .orElseGet(this::createKey);

    System.out.println();
    System.out.println("Alias " + alias + " maps to key id " + keyId);
  }

  public KmsClient getClient() {
    return client;
  }

  public String getKeyId() {
    return keyId;
  }

  private boolean matches(AliasListEntry alias) {
    return ("alias/" + this.alias).equals(alias.aliasName());
  }

  private List<AliasListEntry> listAliases() {
    String marker = null;
    boolean truncated = false;
    List<AliasListEntry> discoveredAliases = new ArrayList<>();
    do {
      ListAliasesRequest request = ListAliasesRequest.builder().marker(marker).build();
      ListAliasesResponse results = client.listAliases(request);

      discoveredAliases.addAll(results.aliases());
      marker = results.nextMarker();
      truncated = results.truncated();
    } while (truncated);

    return discoveredAliases;
  }

  private String createKey() {
    System.out.println("No matching CMK found, creating a new one (" + this + ")");

    CreateKeyRequest createKeyRequest =
        CreateKeyRequest.builder()
            .keySpec(algorithmFamily.getKmsKeySpec())
            .keyUsage(KeyUsageType.SIGN_VERIFY)
            .build();

    CreateKeyResponse createKeyResponse = client.createKey(createKeyRequest);
    String keyId = createKeyResponse.keyMetadata().keyId();

    System.out.println("Created CMK. Creating alias for key=" + keyId);

    CreateAliasRequest createAliasRequest =
        CreateAliasRequest.builder().aliasName("alias/" + alias).targetKeyId(keyId).build();

    client.createAlias(createAliasRequest);

    System.out.println("Created alias=" + alias + " to key=" + keyId);

    return keyId;
  }

  private PublicKey getPublicKey() {
    try {
      System.out.println("Getting public key for key=" + keyId);

      GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();

      GetPublicKeyResponse getPublicKeyResponse = client.getPublicKey(getPublicKeyRequest);
      byte[] publicKeyBytes = getPublicKeyResponse.publicKey().asByteArray();

      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
      PublicKey publicKey =
          KeyFactory.getInstance(
                  algorithmFamily.getKeyFactoryAlgorithm(), BouncyCastleProvider.PROVIDER_NAME)
              .generatePublic(publicKeySpec);

      System.out.println("Public key for key=" + keyId + ":\n" + publicKey);

      return publicKey;
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  public String generateCSR(String commonName) {
    try {
      PublicKey publicKey = getPublicKey();

      X500Name csrSubject = new X500Name("CN=" + commonName);

      ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
      extensionsGenerator.addExtension(
          Extension.basicConstraints, false, new BasicConstraints(false));

      PKCS10CertificationRequestBuilder csrBuilder =
          new JcaPKCS10CertificationRequestBuilder(csrSubject, publicKey);
      csrBuilder.addAttribute(
          PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

      ContentSigner contentSigner = Signing.createContentSigner(this, algorithmFamily);
      PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);

      PemObjectGenerator miscPEMGenerator = new MiscPEMGenerator(csr);
      StringWriter csrStringWriter = new StringWriter();
      PemWriter csrPEMWriter = new PemWriter(csrStringWriter);
      csrPEMWriter.writeObject(miscPEMGenerator);
      csrPEMWriter.close();

      String csrPEM = csrStringWriter.toString();

      System.out.println("Generated CSR:\n" + csrPEM);

      return csrPEM;
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  public AlgorithmFamily getAlgorithmFamily() {
    return algorithmFamily;
  }

  @Override
  public String toString() {
    return "AsymmetricCMK{"
        + "alias='"
        + alias
        + '\''
        + ", algorithmFamily='"
        + algorithmFamily.getFamilyName()
        + '\''
        + '}';
  }

  public static AsymmetricCMK.Builder builder() {
    return new AsymmetricCMK.Builder();
  }

  public static class Builder {

    private String alias;
    private AlgorithmFamily algorithmFamily;

    private Builder() {}

    public Builder withAlias(String alias) {
      this.alias = alias;
      return this;
    }

    public Builder withAlgorithmFamily(AlgorithmFamily algorithmFamily) {
      this.algorithmFamily = algorithmFamily;
      return this;
    }

    public AsymmetricCMK getOrCreate() {
      return new AsymmetricCMK(alias, algorithmFamily);
    }
  }
}
