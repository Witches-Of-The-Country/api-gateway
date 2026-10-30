package com.dungeoneer.api_gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.server.mvc.filter.AfterFilterFunctions;
import org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RequestPredicates;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

@Configuration(proxyBeanMethods = false)
public class GatewayRoutesConfig {

    @Bean
    public RouterFunction<ServerResponse> gatewayRoutes(
            @Value("${auth.service.url}") String authServiceUrl,
            @Value("${character.service.url}") String characterServiceUrl) {

        return GatewayRouterFunctions.route("auth-service-route")
                .route(RequestPredicates.path("/api/auth/**"), HandlerFunctions.http())
                .before(BeforeFilterFunctions.uri(authServiceUrl))
                .before(BeforeFilterFunctions.removeRequestHeader("Origin"))
                .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Origin"))
                .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Credentials"))
                .build()
                .and(GatewayRouterFunctions.route("reference-data-route")
                        .route(RequestPredicates.path("/api/reference/**"), HandlerFunctions.http())
                        .before(BeforeFilterFunctions.uri(characterServiceUrl))
                        .before(BeforeFilterFunctions.removeRequestHeader("Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Credentials"))
                        .build())
                .and(GatewayRouterFunctions.route("character-service-route")
                        .route(RequestPredicates.path("/api/characters/**"), HandlerFunctions.http())
                        .before(BeforeFilterFunctions.uri(characterServiceUrl))
                        .before(BeforeFilterFunctions.removeRequestHeader("Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Credentials"))
                        .build())
                .and(GatewayRouterFunctions.route("character-service-docs")
                        .route(RequestPredicates.path("/v3/api-docs/characters"), HandlerFunctions.http())
                        .before(BeforeFilterFunctions.uri(characterServiceUrl))
                        .before(BeforeFilterFunctions.setPath("/v3/api-docs"))
                        .before(BeforeFilterFunctions.removeRequestHeader("Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Credentials"))
                        .build())
                .and(GatewayRouterFunctions.route("auth-service-docs")
                        .route(RequestPredicates.path("/v3/api-docs/auth"), HandlerFunctions.http())
                        .before(BeforeFilterFunctions.uri(authServiceUrl))
                        .before(BeforeFilterFunctions.setPath("/v3/api-docs"))
                        .before(BeforeFilterFunctions.removeRequestHeader("Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Origin"))
                        .after(AfterFilterFunctions.removeResponseHeader("Access-Control-Allow-Credentials"))
                        .build());
    }
}
