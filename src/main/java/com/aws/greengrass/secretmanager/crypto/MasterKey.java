/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.secretmanager.crypto;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;

public interface MasterKey {

    JceMasterKey getMasterKey();
}
