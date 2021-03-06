package com.qinchy.jwtdemo.config;

import com.qinchy.jwtdemo.model.Audience;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Administrator
 */
@Configuration
public class AudienceConfig {
    @Bean
    public Audience getAudience(){
        Audience audienceEntity = new Audience();
        audienceEntity.setBase64Secret("AUDIENCE");
        audienceEntity.setClientId("AUDIENCE_ID1");
        audienceEntity.setExpiresSecond(7200L);
        audienceEntity.setName("AUDIENCE_TEST");
        return audienceEntity;
    }
}
