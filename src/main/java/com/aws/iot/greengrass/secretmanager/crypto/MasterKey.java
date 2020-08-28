package com.aws.iot.greengrass.secretmanager.crypto;

import com.amazonaws.encryptionsdk.jce.JceMasterKey;

public interface MasterKey {

    JceMasterKey getMasterKey();
}
