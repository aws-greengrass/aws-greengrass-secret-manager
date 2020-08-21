package com.aws.iot.greengrass.secretmanager.model;

import com.aws.iot.evergreen.testcommons.testutilities.EGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith({MockitoExtension.class, EGExtension.class})
class SecretConfigurationTest {

    @Test
    void GIVEN_secret_builder_WHEN_called_THEN_secret_created() {
        SecretConfiguration configuration = SecretConfiguration.builder().arn("arn")
                .labels(Arrays.asList(new String[]{"label1", "label2"})).build();

        assertEquals("arn", configuration.getArn());
        assertThat(configuration.getLabels(), hasItem("label1"));
        assertThat(configuration.getLabels(), hasItem("label2"));

        SecretConfiguration configuration2 = SecretConfiguration.builder().arn("arn")
                .labels(Arrays.asList(new String[]{"label1", "label2"})).build();

        assertEquals(configuration, configuration2);

        assertThrows(NullPointerException.class, () -> SecretConfiguration.builder().build());
    }
}
