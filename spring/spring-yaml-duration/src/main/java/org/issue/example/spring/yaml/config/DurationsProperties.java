package org.issue.example.spring.yaml.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DurationUnit;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * @Author: Mr.Zhao
 * @Description: java.time.Duration在yaml文件的配置
 * @see <a href="https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#features.external-config.typesafe-configuration-properties.conversion.durations">参考地址</a>
 * @Date:Create：in 2024/2/2 17:52
 * @Modified By:
 */
@ConfigurationProperties(prefix = "spring.converting.durations")
public class DurationsProperties {

    /**
     * 使用了@DurationUnit注解，单位（秒）
     */
    @DurationUnit(ChronoUnit.SECONDS)
    private Duration unitDuration;

    /**
     * 默认毫秒
     */
    private Duration millisecond;

    /**
     * 值和单位是耦合的
     */
    private Duration formatDuration;


    public Duration getUnitDuration() {
        return unitDuration;
    }

    public void setUnitDuration(Duration unitDuration) {
        this.unitDuration = unitDuration;
    }

    public Duration getMillisecond() {
        return millisecond;
    }

    public void setMillisecond(Duration millisecond) {
        this.millisecond = millisecond;
    }

    public Duration getFormatDuration() {
        return formatDuration;
    }

    public void setFormatDuration(Duration formatDuration) {
        this.formatDuration = formatDuration;
    }
}
