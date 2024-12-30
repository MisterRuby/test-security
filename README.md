## SecurityFilterChain
```kotlin
@Bean
@ConditionalOnMissingBean(SecurityFilterChain::class) // 빈이 없을 때만 등록
fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http.csrf { it.disable() }
        .authorizeHttpRequests { auth ->
            auth.requestMatchers("/login").permitAll()
                .anyRequest().authenticated()
        }
        .formLogin { it.disable() } // 기본 로그인 폼 비활성화
        .httpBasic { it.disable() } // 기본 브라우저 인증 비활성화
        .logout { logout -> logout.permitAll() }

    return http.build()
}
```
- 기본적으로 SecurityFilterChain 을 Bean 으로 등록하고 있으며 필요할 경우 SecurityFilterChain 을 새로 Bean 으로 등록하여 사용하면 된다.
    - 요청 url 별 권한 재설정, cors 설정 추가 등
