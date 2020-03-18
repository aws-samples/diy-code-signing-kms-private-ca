package com.amazonaws.acmpcakms.examples;

import com.amazonaws.services.acmpca.model.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.Security;

public class Runner {

    private static final String ROOT_COMMON_NAME = "CodeSigningRoot";
    private static final String SUBORDINATE_COMMON_NAME = "CodeSigningSubordinate";
    private static final String END_ENTITY_COMMON_NAME = "CodeSigningCertificate";
    private static final String CMK_ALIAS = "CodeSigningCMK";
    private static final String TBS_DATA = "The data that I want signed";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(final String[] args) throws Exception {

        /* Creating a CA hierarcy in ACM Private CA. This CA hiearchy consistant of a Root and subordinate CA */
        System.out.println("Creating a CA hierarchy\n");

        PrivateCA rootPrivateCA = PrivateCA.builder()
                .withCommonName(ROOT_COMMON_NAME)
                .withType(CertificateAuthorityType.ROOT)
                .getOrCreate();

        PrivateCA subordinatePrivateCA = PrivateCA.builder()
                .withIssuer(rootPrivateCA)
                .withCommonName(SUBORDINATE_COMMON_NAME)
                .withType(CertificateAuthorityType.SUBORDINATE)
                .getOrCreate();

        /* Creating a asymmetric key pair using AWS KMS */
        System.out.println();
        System.out.println("Creating a asymmetric key pair using AWS KMS\n");

        AsymmetricCMK codeSigningCMK = AsymmetricCMK.builder()
                .withAlias(CMK_ALIAS)
                .getOrCreate();

        /* Creating a asymmetric key pair using AWS KMS */
        System.out.println();
        System.out.println("Creating a CSR(Certificate signing request) for creating a code signing certificate\n");
        String codeSigningCSR = codeSigningCMK.generateCSR(END_ENTITY_COMMON_NAME);

        /* Issuing the code signing certificate from ACM Private CA */
        System.out.println();
        System.out.println("Issuing a code signing certificate from ACM Private CA\n");
        GetCertificateResult codeSigningCertificate = subordinatePrivateCA.issueCodeSigningCertificate(codeSigningCSR);

        /* Creating a custom code signing object */
        System.out.println();
        System.out.println("Creating a custom code signing object\n");
        CustomCodeSigningObject customCodeSigningObject = CustomCodeSigningObject.builder()
                .withAsymmetricCMK(codeSigningCMK)
                .withDataBlob(TBS_DATA.getBytes(StandardCharsets.UTF_8))
                .withCertificate(codeSigningCertificate.getCertificate())
                .build();

        /* Creating a custom code signing object */
        System.out.println();
        System.out.println("Object was signed successfully\n");

        /* Verifying the authenticity of the signature and the integrity of the signed data */
        System.out.println();
        System.out.println("Verifying the authenticity of the signature and the integrity of the signed data\n");
        String rootCACertificate = rootPrivateCA.getCertificate();
        String customCodeSigningObjectCertificateChain = codeSigningCertificate.getCertificate() + "\n" + codeSigningCertificate.getCertificateChain();

        CustomCodeSigningObject.getInstance(customCodeSigningObject.toString())
                .validate(rootCACertificate, customCodeSigningObjectCertificateChain);
    }
}
