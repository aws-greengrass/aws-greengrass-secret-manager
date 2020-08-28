package com.aws.iot.greengrass.secretmanager.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
public class SecretDocument {
    List<AWSSecretResponse> secrets;
}
