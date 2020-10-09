/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.model;

import com.aws.greengrass.secretmanager.model.v1.GetSecretValueError;
import com.aws.greengrass.secretmanager.model.v1.GetSecretValueResult;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
public class GetSecretResponse {
    GetSecretValueResult secret;
    GetSecretValueError error;
}
