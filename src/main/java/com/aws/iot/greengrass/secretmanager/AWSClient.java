package com.aws.iot.greengrass.secretmanager;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.DecryptionFailureException;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.InternalServiceErrorException;
import com.amazonaws.services.secretsmanager.model.InvalidParameterException;
import com.amazonaws.services.secretsmanager.model.InvalidRequestException;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.aws.iot.evergreen.tes.LazyCredentialProvider;
import com.aws.iot.evergreen.util.Utils;
import com.aws.iot.greengrass.secretmanager.exception.SecretManagerException;

import javax.inject.Inject;

public class AWSClient {

    private final AWSSecretsManager secretsManagerClient;

    /**
     * Constructor which utilized TES for initializing AWS client.
     * @param credentialProvider TES credential provider
     */
    @Inject
    public AWSClient(LazyCredentialProvider credentialProvider) {
        this.secretsManagerClient = AWSSecretsManagerClientBuilder
                .standard()
                .withCredentials(credentialProvider)
                .build();
    }

    // Constructor used for testing.
    AWSClient(AWSSecretsManager secretsManager) {
        this.secretsManagerClient = secretsManager;
    }

    /**
     * Fetch secret from AWS cloud.
     * @param request AWS request for fetching secret from cloud
     * @return AWS secret response
     * @throws SecretManagerException If there is a problem fetching secret
     */
    public GetSecretValueResult getSecret(GetSecretValueRequest request) throws SecretManagerException {
        // TODO: Add retry for fetches
        validateInput(request);
        String errorMsg = String.format("Exception occurred while fetching secrets from AWSSecretsManager for key %s",
                request.getSecretId());
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
        if (Utils.isEmpty(request.getSecretId())) {
            throw new IllegalArgumentException("Invalid secret request, secret id is required");
        }

        if (Utils.isEmpty(request.getVersionId()) && Utils.isEmpty(request.getVersionStage())) {
            throw new IllegalArgumentException("Invalid secret request, either version Id or stage is required");
        }
    }
}
