/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.tes.LazyCredentialProvider;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.ProxyUtils;
import com.aws.greengrass.util.RetryUtils;
import com.aws.greengrass.util.Utils;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import javax.inject.Inject;

public class AWSSecretClient {

    private final SecretsManagerClient secretsManagerClient;
    private final Logger logger = LogManager.getLogger(AWSSecretClient.class);
    private final RetryUtils.RetryConfig retryConfig =
            RetryUtils.RetryConfig.builder().maxAttempt(3).maxRetryInterval(Duration.ofMillis(200)).retryableExceptions(
                    Arrays.asList(IOException.class, InternalServiceErrorException.class,
                            ResourceNotFoundException.class)).build();

    /**
     * Constructor which utilizes  TES for initializing AWS client.
     *
     * @param credentialProvider  TES credential provider
     * @param deviceConfiguration device configuration properties from kernel
     */
    @Inject
    public AWSSecretClient(LazyCredentialProvider credentialProvider, DeviceConfiguration deviceConfiguration) {
        Region region = Region.of(Coerce.toString(deviceConfiguration.getAWSRegion()));
        this.secretsManagerClient = SecretsManagerClient.builder().httpClient(ProxyUtils.getSdkHttpClient())
                .credentialsProvider(credentialProvider).region(region).build();
    }

    // Constructor used for testing.
    AWSSecretClient(SecretsManagerClient secretsManager) {
        this.secretsManagerClient = secretsManager;
    }

    /**
     * Fetch secret from AWS cloud.
     *
     * @param request AWS request for fetching secret from cloud
     * @return AWS secret response
     * @throws SecretManagerException If there is a problem fetching secret
     */
    public GetSecretValueResponse getSecret(GetSecretValueRequest request) throws SecretManagerException {
        String errorMsg = String.format("Exception occurred while fetching secrets "
                        + "from AWSSecretsManager for secret: %s, version: %s, label: %s", request.secretId(),
                request.versionId(), request.versionStage());
        try {
            validateInput(request);
            GetSecretValueResponse response =
                    RetryUtils.runWithRetry(retryConfig, () -> secretsManagerClient.getSecretValue(request),
                            "get-secret-response", logger);
            validateResponse(response);
            return response;
        } catch (Exception e) {
            logger.atError().cause(e).log(errorMsg);
            throw new SecretManagerException(errorMsg, e);
        }
    }

    private void validateResponse(GetSecretValueResponse response) {
        String errorStr = "Invalid secret response, %s is missing";
        if (Utils.isEmpty(response.versionId())) {
            throw new IllegalArgumentException(String.format(errorStr, "version Id"));
        }
        if (Utils.isEmpty(response.arn())) {
            throw new IllegalArgumentException(String.format(errorStr, "arn"));
        }
        if (Utils.isEmpty(response.name())) {
            throw new IllegalArgumentException(String.format(errorStr, "name"));
        }
        if (response.createdDate() == null) {
            throw new IllegalArgumentException(String.format(errorStr, "created date"));
        }
        if (!response.hasVersionStages() || response.versionStages().isEmpty()) {
            throw new IllegalArgumentException(String.format(errorStr, "version stages"));
        }
        if (Utils.isEmpty(response.secretString()) && response.secretBinary() == null) {
            throw new IllegalArgumentException(String.format(errorStr, "both secret string and binary"));
        }
    }

    private void validateInput(GetSecretValueRequest request) {
        if (Utils.isEmpty(request.secretId())) {
            throw new IllegalArgumentException("invalid secret request, secret id is required");
        }

        if (Utils.isEmpty(request.versionId()) && Utils.isEmpty(request.versionStage())) {
            throw new IllegalArgumentException("invalid secret request, either version Id or stage is required");
        }
    }
}
