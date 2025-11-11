package com.amazonaws.acmpcakms.examples;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class CertificateUtils {

  public static X509CertificateHolder fromPEM(String certificatePEM) throws Exception {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    Certificate certificate =
        certificateFactory.generateCertificate(
            new ByteArrayInputStream(certificatePEM.getBytes(StandardCharsets.UTF_8)));
    return new X509CertificateHolder(certificate.getEncoded());
  }

  public static String toPEM(X509CertificateHolder certificateHolder) throws IOException {
    StringWriter stringWriter = new StringWriter();
    try (PemWriter pemWriter = new PemWriter(stringWriter)) {
      PemObject pemObject = new PemObject("CERTIFICATE", certificateHolder.getEncoded());
      pemWriter.writeObject(pemObject);
    }
    return stringWriter.toString();
  }

  public static X509CertificateHolder toCertificateHolder(Certificate certificate)
      throws Exception {
    return new X509CertificateHolder(certificate.getEncoded());
  }

  public static X509Certificate toCertificate(X509CertificateHolder certificate) throws Exception {
    return new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(certificate);
  }

  public static Collection<X509CertificateHolder> toCertificateHolders(String certificateChainPEM)
      throws Exception {
    Collection<X509CertificateHolder> certificates = new ArrayList<>();
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

    ByteArrayInputStream inputStream =
        new ByteArrayInputStream(certificateChainPEM.getBytes(StandardCharsets.UTF_8));
    Collection<? extends Certificate> certCollection =
        certificateFactory.generateCertificates(inputStream);

    for (Certificate cert : certCollection) {
      certificates.add(toCertificateHolder(cert));
    }

    return certificates;
  }
}
