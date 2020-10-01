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
public class GetSecretValueRequest {
    /**
     * The unique identifier of the secret.
     */
    @JsonProperty("SecretId")
    private String secretId;
    /**
     * The unique identifier of the secret version.
     */
    @JsonProperty("VersionId")
    private String versionId;
    /**
     * The staging label attached to the secret version.
     */
    @JsonProperty("VersionStage")
    private String versionStage;
}
