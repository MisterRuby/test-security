package ruby.commonsecurity.security.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class CorsConfig(private val corsProperties: CorsProperties) {
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val resourceServerConfiguration = CorsConfiguration()
        resourceServerConfiguration.allowedOrigins = corsProperties.resourceServers // 허용할 도메인
        resourceServerConfiguration.allowedMethods = listOf("GET", "POST") // 허용할 HTTP 메서드
        resourceServerConfiguration.allowedHeaders = listOf("*") // 허용할 헤더
        resourceServerConfiguration.allowCredentials = true // 쿠키를 포함한 자격 증명 허용

        val clientServersConfiguration = CorsConfiguration()
        clientServersConfiguration.allowedOrigins = corsProperties.allowedOrigins // 허용할 도메인
        clientServersConfiguration.allowedMethods = listOf("GET", "POST") // 허용할 HTTP 메서드
        clientServersConfiguration.allowedHeaders = listOf("*") // 허용할 헤더
        clientServersConfiguration.allowCredentials = true // 쿠키를 포함한 자격 증명 허용

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/jwk", resourceServerConfiguration)       // corsProperties.resourceServers 도메인에만 허용
        source.registerCorsConfiguration("/auth/**", clientServersConfiguration)    // corsProperties.allowedOrigins 도메인에만 허용
        return source
    }
}

@Component
@ConfigurationProperties(prefix = "cors")
class CorsProperties {
    var resourceServers: List<String> = emptyList()
    var allowedOrigins: List<String> = emptyList()
}
