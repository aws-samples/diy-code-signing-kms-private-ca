package com.amazonaws.acmpcakms.examples.algorithms.rsa;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import software.amazon.awssdk.services.acmpca.model.KeyAlgorithm;
import software.amazon.awssdk.services.acmpca.model.SigningAlgorithm;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

public class RSA3072Family implements AlgorithmFamily {

  @Override
  public KeySpec getKmsKeySpec() {
    return KeySpec.RSA_3072;
  }

  @Override
  public SigningAlgorithmSpec getKmsSigningAlgorithm() {
    return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384;
  }

  @Override
  public KeyAlgorithm getPcaKeyAlgorithm() {
    return KeyAlgorithm.RSA_3072;
  }

  @Override
  public SigningAlgorithm getPcaSigningAlgorithm() {
    return SigningAlgorithm.SHA384_WITHRSA;
  }

  @Override
  public String getBouncyCastleAlgorithmName() {
    return "SHA384WITHRSA";
  }

  @Override
  public String getFamilyName() {
    return "RSA3072";
  }

  @Override
  public String getKeyFactoryAlgorithm() {
    return "RSA";
  }
}
