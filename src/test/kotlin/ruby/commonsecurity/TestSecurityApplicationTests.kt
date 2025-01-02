package ruby.commonsecurity

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.mock.web.MockCookie
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import ruby.commonsecurity.entity.AccountStatus
import ruby.commonsecurity.entity.UserInfo
import ruby.commonsecurity.entity.UserInfoRepository
import ruby.commonsecurity.security.jwt.JwtUtils

@RestController
class TestController{

    @GetMapping("/test")
    fun test() {
        println("test call")
    }
}

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class LoginTests {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var userInfoRepository: UserInfoRepository

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var jwtUtils: JwtUtils

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @BeforeEach
    fun setUp() {
        userInfoRepository.save(
            UserInfo(
                email = "approved_user@example.com",
                password = passwordEncoder.encode("password123"),
                name = "Test User",
                accountStatus = AccountStatus.APPROVED
            )
        )
    }

    @Test
    fun `로그인 성공 테스트1`() {
        testLoginSuccess("http://www.test.com")
    }

    @Test
    fun `로그인 성공 테스트2`() {
        testLoginSuccess("http://www.example.com")
    }

    fun testLoginSuccess(origin: String) {
        val loginRequest = """
            {
                "email": "approved_user@example.com",
                "password": "password123"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/auth/login")
                .with(csrf())
                .header(HttpHeaders.ORIGIN, origin)
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginRequest)
        )
            .andExpect(status().isOk) // 200 상태 확인
            .andExpect(jsonPath("$.email").value("approved_user@example.com"))
            .andExpect(jsonPath("$.accessToken").exists())
            .andExpect(cookie().exists("refreshToken"))
            .andDo { result ->
                val responseContent = result.response.contentAsString
                val responseData: Map<String, String> = objectMapper.readValue(responseContent)
                val accessToken = responseData["accessToken"] as String
                val refreshToken = result.response.cookies.firstOrNull { it.name == "refreshToken" }?.value

                println("Access Token: $accessToken")
                println("Refresh Token: $refreshToken")
            }
    }

    @Test
    fun `로그인 실패 - 잘못된 비밀번호`() {
        val loginRequest = """
            {
                "email": "approved_user@example.com",
                "password": "wrongpassword"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/auth/login")
                .header(HttpHeaders.ORIGIN, "http://www.test.com")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginRequest)
        )
            .andExpect(status().isUnauthorized) // 401 상태 확인
    }

    @Test
    fun `로그인 실패 - 존재하지 않는 사용자`() {
        val loginRequest = """
            {
                "email": "non_existent_user@example.com",
                "password": "password123"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/auth/login")
                .with(csrf())
                .header(HttpHeaders.ORIGIN, "http://www.test.com")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginRequest)
        )
            .andExpect(status().isUnauthorized) // 401 상태 확인
    }

    @Test
    fun `로그인 실패 - 허용하지 않는 ORIGIN`() {
        val loginRequest = """
            {
                "email": "approved_user@example.com",
                "password": "password123"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/auth/login")
                .with(csrf())
                .header(HttpHeaders.ORIGIN, "http://www.test1.com")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginRequest)
        )
            .andExpect(status().isForbidden) // 403 상태 확인
    }


    @Test
    fun `인증 요청 성공`() {
        val accessToken = jwtUtils.generateToken("approved_user@example.com")

        mockMvc.perform(
            get("/test")
                .header(HttpHeaders.ORIGIN, "http://www.test.com")
                .header("Authorization", "Bearer $accessToken") // JWT 포함
        )
            .andExpect(status().isOk)
    }

    @Test
    fun `인증 요청 실패 - 잘못된 AccessToken`() {
        // 잘못된 accessToken
        val accessToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhcHByb3ZlZF91c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzM1NTk0NTM4LCJleHAiOjE3MzU2ODA5Mzh9.25ZHRNLbDvGXrcAQPRsQRS7Il8w8nsQCFn8wZOAMdSE"

        mockMvc.perform(
            get("/test")
                .header("Authorization", "Bearer $accessToken") // JWT 포함
        )
            .andExpect(status().isForbidden)
    }


    @Test
    fun `AccessToken 재발급 성공`() {
        val refreshToken = jwtUtils.generateToken("approved_user@example.com")

        mockMvc.perform(
            get("/auth/refresh-token")
                .header(HttpHeaders.ORIGIN, "http://www.test.com")
                .cookie(MockCookie("refreshToken", refreshToken))
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.accessToken").exists())
            .andDo { result ->
                val responseContent = result.response.contentAsString
                val responseData: Map<String, String> = objectMapper.readValue(responseContent)
                val accessToken = responseData["accessToken"] as String

                println("Access Token: $accessToken")
            }
    }

    @Test
    fun `AccessToken 재발급 실패 - 잘못된 refreshToken`() {
        val refreshToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhcHByb3ZlZF91c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzM1NTk0NTM4LCJleHAiOjE3MzU2ODA5Mzh9.25ZHRNLbDvGXrcAQPRsQRS7Il8w8nsQCFn8wZOAMdSE"

        mockMvc.perform(
            get("/auth/refresh-token")
                .header(HttpHeaders.ORIGIN, "http://www.test.com")
                .cookie(MockCookie("refreshToken", refreshToken))
        )
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `jwk 요청 성공`() {
        mockMvc.perform(
            get("/jwk")
                .header(HttpHeaders.ORIGIN, "http://resource-server.com")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.kty").exists())
            .andExpect(jsonPath("$.alg").exists())
            .andExpect(jsonPath("$.use").exists())
            .andExpect(jsonPath("$.n").exists())
            .andExpect(jsonPath("$.e").exists())
            .andDo { result ->
                val responseContent = result.response.contentAsString
                val responseData: Map<String, String> = objectMapper.readValue(responseContent)

                println("responseData: $responseData")
            }
    }

    @Test
    fun `jwk 요청 실패 - 허용되지 않은 ORIGIN 도메인`() {
        mockMvc.perform(
            get("/jwk")
                .header(HttpHeaders.ORIGIN, "http://www.test.com")
        )
            .andExpect(status().isForbidden)
    }


    @Test
    fun `jwk 요청 실패 - 인증된 사용자이지만 허용되지 않은 ORIGIN 도메인`() {
        val accessToken = jwtUtils.generateToken("approved_user@example.com")

        mockMvc.perform(
            get("/jwk")
                .header(HttpHeaders.ORIGIN, "http://www.test.com")
                .header("Authorization", "Bearer $accessToken") // JWT 포함
        )
            .andExpect(status().isForbidden)
    }
}
