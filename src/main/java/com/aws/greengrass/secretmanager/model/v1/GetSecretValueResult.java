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

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Date;

@Builder(toBuilder = true)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class GetSecretValueResult {
    /**
     * ARN of the secret.
     */
    @JsonProperty("ARN")
    private String arn;

    /**
     * The date and time that this version of the secret was created.
     */
    @JsonProperty("CreatedDate")
    private Date createdDate;

    /**
     * The friendly name of the secret.
     */
    @JsonProperty("Name")
    private String name;

    /**
     * The decrypted part of the protected secret information that was originally provided as binary data
     * in the form of a byte array.
     */
    @JsonProperty("SecretBinary")
    private ByteBuffer secretBinary;

    /**
     * The decrypted part of the protected secret information that was originally provided as a string.
     */
    @JsonProperty("SecretString")
    private String secretString;

    /**
     * The unique identifier of this version of the secret.
     */
    @JsonProperty("VersionId")
    private String versionId;

    /**
     * A list of all of the staging labels currently attached to this version of the secret.
     */
    @JsonProperty("VersionStages")
    private Collection<String> versionStages;
}
