/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.model.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder(toBuilder = true)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class GetSecretValueError {
    /**
     * Status code for the error response.
     */
    @JsonProperty("Status")
    private int status;

    /**
     * Error message for the error response.
     */
    @JsonProperty("Message")
    private String message;
}
