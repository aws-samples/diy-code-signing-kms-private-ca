package com.amazonaws.acmpcakms.examples.algorithms.ecc;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import software.amazon.awssdk.services.acmpca.model.KeyAlgorithm;
import software.amazon.awssdk.services.acmpca.model.SigningAlgorithm;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

public class ECP256Family implements AlgorithmFamily {

  @Override
  public KeySpec getKmsKeySpec() {
    return KeySpec.ECC_NIST_P256;
  }

  @Override
  public SigningAlgorithmSpec getKmsSigningAlgorithm() {
    return SigningAlgorithmSpec.ECDSA_SHA_256;
  }

  @Override
  public KeyAlgorithm getPcaKeyAlgorithm() {
    return KeyAlgorithm.EC_PRIME256_V1;
  }

  @Override
  public SigningAlgorithm getPcaSigningAlgorithm() {
    return SigningAlgorithm.SHA256_WITHECDSA;
  }

  @Override
  public String getBouncyCastleAlgorithmName() {
    return "SHA256WITHECDSA";
  }

  @Override
  public String getFamilyName() {
    return "ECP256";
  }

  @Override
  public String getKeyFactoryAlgorithm() {
    return "EC";
  }
}
