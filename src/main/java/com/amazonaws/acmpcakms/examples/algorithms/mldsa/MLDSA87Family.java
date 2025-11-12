package com.amazonaws.acmpcakms.examples.algorithms.mldsa;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import software.amazon.awssdk.services.acmpca.model.KeyAlgorithm;
import software.amazon.awssdk.services.acmpca.model.SigningAlgorithm;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

public class MLDSA87Family implements AlgorithmFamily {

  @Override
  public KeySpec getKmsKeySpec() {
    return KeySpec.ML_DSA_87;
  }

  @Override
  public SigningAlgorithmSpec getKmsSigningAlgorithm() {
    return SigningAlgorithmSpec.ML_DSA_SHAKE_256;
  }

  @Override
  public KeyAlgorithm getPcaKeyAlgorithm() {
    return KeyAlgorithm.ML_DSA_87;
  }

  @Override
  public SigningAlgorithm getPcaSigningAlgorithm() {
    return SigningAlgorithm.ML_DSA_87;
  }

  @Override
  public String getBouncyCastleAlgorithmName() {
    return "ML-DSA-87";
  }

  @Override
  public String getFamilyName() {
    return "MLDSA87";
  }

  @Override
  public String getKeyFactoryAlgorithm() {
    return "ML-DSA";
  }
}
