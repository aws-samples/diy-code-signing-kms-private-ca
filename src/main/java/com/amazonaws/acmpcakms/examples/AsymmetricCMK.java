package com.amazonaws.acmpcakms.examples;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AsymmetricCMK {

    private final AWSKMS client;
    private final String alias;
    private final String keyId;

    private AsymmetricCMK(final String alias) {
        if (Objects.isNull(alias) || alias.isBlank()) {
            throw new IllegalArgumentException("A non-empty alias must be specified");
        }

        this.client = AWSKMSClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        this.alias = alias;

        List<AliasListEntry> discoveredAliases = listAliases();

        this.keyId = discoveredAliases.stream()
                .filter(this::matches)
                .map(AliasListEntry::getTargetKeyId)
                .findFirst()
                .orElseGet(this::createKey);

        System.out.println();
        System.out.println("Alias " + alias + " maps to key id " + keyId);
    }

    public AWSKMS getClient() {
        return client;
    }

    public String getKeyId() {
        return keyId;
    }

    private boolean matches(final AliasListEntry alias) {
        return ("alias/" + this.alias).equals(alias.getAliasName());
    }

    private List<AliasListEntry> listAliases() {
        String marker = null;
        boolean truncated = false;
        List<AliasListEntry> discoveredAliases = new ArrayList<>();
        do {
            ListAliasesResult results = client.listAliases(new ListAliasesRequest()
                    .withMarker(marker));

            discoveredAliases.addAll(results.getAliases());
            marker = results.getNextMarker();
            truncated = results.getTruncated();
        } while (truncated);

        return discoveredAliases;
    }

    private String createKey() {
        System.out.println("No matching CMK found, creating a new one (" + this + ")");

        CreateKeyRequest createKeyRequest = new CreateKeyRequest()
                .withCustomerMasterKeySpec(CustomerMasterKeySpec.RSA_2048)
                .withKeyUsage(KeyUsageType.SIGN_VERIFY);

        String keyId = client.createKey(createKeyRequest)
                .getKeyMetadata()
                .getKeyId();

        System.out.println("Created CMK. Creating alias for key=" + keyId);

        CreateAliasRequest createAliasRequest = new CreateAliasRequest()
                .withAliasName("alias/" + alias)
                .withTargetKeyId(keyId);

        client.createAlias(createAliasRequest);

        System.out.println("Created alias=" + alias + " to key=" + keyId);

        return keyId;
    }

    private PublicKey getPublicKey() {
        try {
            System.out.println("Getting public key for key=" + keyId);

            GetPublicKeyRequest getPublicKeyRequest = new GetPublicKeyRequest()
                    .withKeyId(keyId);

            byte[] publicKeyBytes = client.getPublicKey(getPublicKeyRequest)
                    .getPublicKey()
                    .array();

            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
                    .generatePublic(publicKeySpec);

            System.out.println("Public key for key=" + keyId + ":\n" + publicKey);

            return publicKey;
        } catch (Exception ex) {
           throw new RuntimeException(ex);
        }
    }

    public String generateCSR(final String commonName) {
        try {
            PublicKey publicKey = getPublicKey();

            X500Name csrSubject = new X500Name("CN=" + commonName);

            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(csrSubject, publicKey);
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

            PKCS10CertificationRequest csr = Signing.sign(this, csrBuilder);

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

    @Override
    public String toString() {
        return "AsymmetricCMK{" +
                "alias='" + alias + '\'' +
                '}';
    }

    public static AsymmetricCMK.Builder builder() {
        return new AsymmetricCMK.Builder();
    }

    public static class Builder {

        private String alias;

        private Builder() {}

        public Builder withAlias(final String alias) {
            this.alias = alias;
            return this;
        }

        public AsymmetricCMK getOrCreate() {
            return new AsymmetricCMK(alias);
        }
    }
}
