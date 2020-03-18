## DIY code signing using AWS KMS and ACM Private CA

## Instructions

1. Ensure that you have set up credentials per https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html

2. The credentials used should have permissions to invoke both ACM and ACM private CA API's. You can find managed policies here for ACM and ACM Private CA. Please follow least privilege principles for security and only provide permissions as needed.

https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaAuthAccess.html

https://docs.aws.amazon.com/acm/latest/userguide/authen-awsmanagedpolicies.html

3. Make sure that maven is installed on your system. Maven needs JDK installed as a prerequisite. You can install maven by following the instructions here :

https://maven.apache.org/install.html

At least JDK version 8 is needed.

4. For executing the code, you can use the commands below in the directory where the git repo is cloned

   mvn verify

The above should build and execute the code while showing you printouts for the various steps involved.

## Cleanup

If you do execute the code and do not perform the clean up, you will be accruing costs for the ACM Private CA's that has been setup. Please delete the CA's by going into the AWS Certificate Manager Private CA on the AWS console. Please note that the CA needs to be disabled before you can delete it. Also delete the asymmetric KMS key that was created, you can do this from the AWS KMS service on the AWS console.

You can follow the instructions at the link below :

https://docs.aws.amazon.com/acm-pca/latest/userguide/PCADeleteCA.html

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
