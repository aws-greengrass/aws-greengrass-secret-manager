/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager;

import com.aws.greengrass.secretmanager.exception.SecretManagerException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class AWSSecretClientTest {

    private static final String SECRET_NAME = "EGUnitTest1";
    private static final String SECRET_VALUE = "plainText";
    private static final String ARN = "arn";
    private static final String LATEST_LABEL = "AWSCURRENT";

    @Mock
    SecretsManagerClient mockAwsClient;

    @Test
    void GIVEN_aws_client_WHEN_get_secret_THEN_secret_returned() throws SecretManagerException, IOException {
        GetSecretValueResponse mockResult = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .arn(ARN)
                .createdDate(Instant.now())
                .versionId(UUID.randomUUID().toString())
                .versionStages(Arrays.asList(new String[]{LATEST_LABEL}))
                .name(SECRET_NAME)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResult);
        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(SECRET_NAME).versionStage(LATEST_LABEL).build();
        GetSecretValueResponse result = cloud.getSecret(request);
        assertEquals(SECRET_NAME, result.name());
        assertEquals(SECRET_VALUE, result.secretString());
    }

    @Test
    void GIVEN_aws_client_throws_WHEN_get_secret_THEN_valid_exception_returned(ExtensionContext context) {
        ignoreExceptionOfType(context, IOException.class);
        ignoreExceptionOfType(context, InternalServiceErrorException.class);
        ignoreExceptionOfType(context, DecryptionFailureException.class);
        ignoreExceptionOfType(context, ResourceNotFoundException.class);
        ignoreExceptionOfType(context, InvalidParameterException.class);
        ignoreExceptionOfType(context, InvalidRequestException.class);
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(InternalServiceErrorException.class);
        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(SECRET_NAME).versionStage(LATEST_LABEL).build();
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(DecryptionFailureException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(ResourceNotFoundException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(InvalidParameterException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenThrow(InvalidRequestException.class);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenAnswer(invocation -> {
            throw new IOException();
        }).thenAnswer(invocation -> {
            throw new IOException();
        }).thenAnswer(invocation -> {
            throw new IOException(); });
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));
    }

    @Test
    void GIVEN_aws_client_throws_WHEN_get_secret_THEN_retry_and_return(ExtensionContext context) throws SecretManagerException,
            IOException {
        ignoreExceptionOfType(context, IOException.class);
        GetSecretValueResponse mockResult = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .arn(ARN)
                .createdDate(Instant.now())
                .versionId(UUID.randomUUID().toString())
                .versionStages(Arrays.asList(new String[]{LATEST_LABEL}))
                .name(SECRET_NAME)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenAnswer(invocation -> {
            throw new IOException();
        }).thenAnswer(invocation -> {
            throw new IOException();
        }).thenReturn(mockResult);
        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(SECRET_NAME).versionStage(LATEST_LABEL).build();
        GetSecretValueResponse result = cloud.getSecret(request);
        verify(mockAwsClient, times(3)).getSecretValue(any(GetSecretValueRequest.class));
        assertEquals(SECRET_NAME, result.name());
        assertEquals(SECRET_VALUE, result.secretString());
    }

    @Test
    void GIVEN_aws_client_throws_WHEN_get_invalid_secret_THEN_valid_exception_returned(ExtensionContext context) {
        ignoreExceptionOfType(context, IllegalArgumentException.class);
        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        // empty secret
        GetSecretValueRequest emptyRequest = GetSecretValueRequest.builder().versionStage(LATEST_LABEL).build();
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(emptyRequest));

        // empty secret
        GetSecretValueRequest emptyVersionAndLabel = GetSecretValueRequest.builder().secretId(SECRET_NAME).build();
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(emptyVersionAndLabel));
    }

    @Test
    void GIVEN_aws_client_throws_WHEN_cloud_returns_invalid_secret_THEN_valid_exception_returned(ExtensionContext context) throws SecretManagerException {
        ignoreExceptionOfType(context, IllegalArgumentException.class);

        AWSSecretClient cloud = new AWSSecretClient(mockAwsClient);
        // empty secret
        GetSecretValueRequest request = GetSecretValueRequest.builder().secretId(SECRET_NAME).versionStage(LATEST_LABEL).build();
        // Create a result without arn
        GetSecretValueResponse mockResultWithoutArn = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .createdDate(Instant.now())
                .versionId(UUID.randomUUID().toString())
                .versionStages(Arrays.asList(new String[]{LATEST_LABEL}))
                .name(SECRET_NAME)
                .build();

        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResultWithoutArn);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        GetSecretValueResponse mockResultWithoutName = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .createdDate(Instant.now())
                .versionId(UUID.randomUUID().toString())
                .versionStages(Arrays.asList(new String[]{LATEST_LABEL}))
                .arn(ARN)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResultWithoutName);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        GetSecretValueResponse mockResultWithoutVersionId = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .createdDate(Instant.now())
                .name(SECRET_NAME)
                .versionStages(Arrays.asList(new String[]{LATEST_LABEL}))
                .arn(ARN)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResultWithoutVersionId);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        GetSecretValueResponse mockResultWithoutSecretString = GetSecretValueResponse.builder()
                .versionId(UUID.randomUUID().toString())
                .createdDate(Instant.now())
                .name(SECRET_NAME)
                .versionStages(Arrays.asList(new String[]{LATEST_LABEL}))
                .arn(ARN)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResultWithoutSecretString);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        GetSecretValueResponse mockResultWithoutVersionLabels = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .createdDate(Instant.now())
                .name(SECRET_NAME)
                .versionId(UUID.randomUUID().toString())
                .arn(ARN)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResultWithoutVersionLabels);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        GetSecretValueResponse mockResultWithoutDate = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .versionStages(Arrays.asList(new String[]{LATEST_LABEL}))
                .name(SECRET_NAME)
                .versionId(UUID.randomUUID().toString())
                .arn(ARN)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResultWithoutDate);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

        GetSecretValueResponse mockResultWithEmptyLabels = GetSecretValueResponse.builder()
                .secretString(SECRET_VALUE)
                .createdDate(Instant.now())
                .name(SECRET_NAME)
                .versionStages(Arrays.asList(new String[]{}))
                .versionId(UUID.randomUUID().toString())
                .arn(ARN)
                .build();
        when(mockAwsClient.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(mockResultWithEmptyLabels);
        assertThrows(SecretManagerException.class, () -> cloud.getSecret(request));

    }
}
