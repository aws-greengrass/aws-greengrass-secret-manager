package com.aws.iot.greengrass.secretmanager.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode
public class AWSSecretResponse {
    @NonNull
    String arn;
    @NonNull
    String name;
    @NonNull
    String versionId;
    String encryptedSecretString;
    String encryptedSecretBytes;
    @NonNull
    List<String> versionStages;
    @NonNull
    Instant createdDate;
}
