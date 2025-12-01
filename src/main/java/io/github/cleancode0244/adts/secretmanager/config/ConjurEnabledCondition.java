package io.github.cleancode0244.adts.secretmanager.config;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class ConjurEnabledCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String provider = context.getEnvironment().getProperty("app.secrets.provider");
        return "conjur".equalsIgnoreCase(provider);
    }
}