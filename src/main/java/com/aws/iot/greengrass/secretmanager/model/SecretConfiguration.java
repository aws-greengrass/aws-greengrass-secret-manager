package com.aws.iot.greengrass.secretmanager.model;

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

import java.util.List;

@Value
@Builder
public class SecretConfiguration {
    @NonNull
    String arn;
    List<String> labels;
}
