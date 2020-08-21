package com.aws.iot.greengrass.secretmanager;

import com.aws.iot.evergreen.ipc.services.secret.GetSecretValueResult;
import com.aws.iot.evergreen.tes.LazyCredentialProvider;
import com.aws.iot.evergreen.util.Utils;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import javax.inject.Inject;

public class AWSSecretClient {

    private final SecretsManagerClient secretsManagerClient;

    /**
     * Constructor which utilized TES for initializing AWS client.
     * @param credentialProvider TES credential provider
     */
    @Inject
    public AWSSecretClient(LazyCredentialProvider credentialProvider) {
        this.secretsManagerClient = SecretsManagerClient.builder().credentialsProvider(credentialProvider)
                .build();
    }

    // Constructor used for testing.
    AWSSecretClient(SecretsManagerClient secretsManager) {
        this.secretsManagerClient = secretsManager;
    }

    /**
     * Fetch secret from AWS cloud.
     * @param request AWS request for fetching secret from cloud
     * @return AWS secret response
     * @throws SecretManagerException If there is a problem fetching secret
     */
    public GetSecretValueResponse getSecret(GetSecretValueRequest request) throws SecretManagerException {
        // TODO: Add retry for fetches
        validateInput(request);
        String errorMsg = String.format("Exception occurred while fetching secrets from AWSSecretsManager for key %s",
                request.secretId());
        try {
            return secretsManagerClient.getSecretValue(request);
        } catch (InternalServiceErrorException
                | DecryptionFailureException
                | ResourceNotFoundException
                | InvalidParameterException
                | InvalidRequestException e) {
            throw new SecretManagerException(errorMsg);
        }
    }

    private void validateInput(GetSecretValueRequest request) throws IllegalArgumentException {
        if (Utils.isEmpty(request.secretId())) {
            throw new IllegalArgumentException("Invalid secret request, secret id is required");
        }

        if (Utils.isEmpty(request.versionId()) && Utils.isEmpty(request.versionStage())) {
            throw new IllegalArgumentException("Invalid secret request, either version Id or stage is required");
        }
    }
}
