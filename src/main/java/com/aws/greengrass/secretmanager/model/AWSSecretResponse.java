/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder(toBuilder = true)
@AllArgsConstructor
@NoArgsConstructor
@Data
public class AWSSecretResponse {
    @NonNull
    String arn;
    @NonNull
    String name;
    @NonNull
    String versionId;
    String encryptedSecretString;
    String encryptedSecretBinary;
    @NonNull
    List<String> versionStages;
    @NonNull
    long createdDate;
}
