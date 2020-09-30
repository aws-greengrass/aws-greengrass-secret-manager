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

import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
public class SecretConfiguration {
    @NonNull
    String arn;
    List<String> labels;

    /**
     * Return a list of arn with each label.
     * @return A list of strings of arn with each label
     */
    public List<String> getArnLabelList() {
        List<String> result = new ArrayList<>();
        if (labels != null) {
            for (String label : labels) {
                result.add(arn + label);
            }
        } else {
            result.add(arn);
        }
        return result;
    }
}
