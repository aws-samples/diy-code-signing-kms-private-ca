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
        PrivateCA rootPrivateCA = PrivateCA.builder()
                .withCommonName(ROOT_COMMON_NAME)
                .withType(CertificateAuthorityType.ROOT)
                .getOrCreate();

        PrivateCA subordinatePrivateCA = PrivateCA.builder()
                .withIssuer(rootPrivateCA)
                .withCommonName(SUBORDINATE_COMMON_NAME)
                .withType(CertificateAuthorityType.SUBORDINATE)
                .getOrCreate();

        AsymmetricCMK codeSigningCMK = AsymmetricCMK.builder()
                .withAlias(CMK_ALIAS)
                .getOrCreate();

        String codeSigningCSR = codeSigningCMK.generateCSR(END_ENTITY_COMMON_NAME);
        GetCertificateResult codeSigningCertificate = subordinatePrivateCA.issueCodeSigningCertificate(codeSigningCSR);

        CustomCodeSigningObject customCodeSigningObject = CustomCodeSigningObject.builder()
                .withAsymmetricCMK(codeSigningCMK)
                .withDataBlob(TBS_DATA.getBytes(StandardCharsets.UTF_8))
                .withCertificate(codeSigningCertificate.getCertificate())
                .build();

        String rootCACertificate = rootPrivateCA.getCertificate();
        String customCodeSigningObjectCertificateChain = codeSigningCertificate.getCertificate() + "\n" + codeSigningCertificate.getCertificateChain();

        CustomCodeSigningObject.getInstance(customCodeSigningObject.toString())
                .validate(rootCACertificate, customCodeSigningObjectCertificateChain);
    }
}
