package ruby.commonsecurity

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import ruby.commonsecurity.domain.*
import ruby.commonsecurity.jwt.JwtUtils

@RestController
class TestController{

    @GetMapping("/test")
    fun test() {
        println("test call")
    }
}

//@SpringBootTest(classes = [AuthLibraryConfig::class])
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class LoginTests {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var userInfoRepository: UserInfoRepository

    @Autowired
    private lateinit var companyRepository: CompanyRepository

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var jwtUtils: JwtUtils

    @BeforeEach
    fun setUp() {
        val company = companyRepository.save(
            Company(
                name = "Test Company",
                registrationNumber = "123-45-67890",
                address = "123 Test Street"
            )
        )

        userInfoRepository.save(
            UserInfo(
                email = "approved_user@example.com",
                password = passwordEncoder.encode("password123"),
                name = "Test User",
                company = company,
                accountStatus = AccountStatus.APPROVED
            )
        )
    }


    @Test
    fun `로그인 성공 테스트`() {
        val loginRequest = """
            {
                "email": "approved_user@example.com",
                "password": "password123"
            }
        """.trimIndent()

        mockMvc.perform(
            post("/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginRequest)
        )
            .andExpect(status().isOk) // 200 상태 확인
            .andExpect(header().exists("Authorization"))
            .andDo { result ->
                val authorization = result.response.getHeader("Authorization")
                println("Authorization: $authorization") // 세션 ID 출력
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
            post("/login")
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
            post("/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginRequest)
        )
            .andExpect(status().isUnauthorized) // 401 상태 확인
    }

    @Test
    fun `인증 요청 - JWT`() {
        val jwt = jwtUtils.generateAccessToken("approved_user@example.com")

        mockMvc.perform(
            get("/test")
                .header("Authorization", "Bearer $jwt") // JWT 포함
        )
            .andExpect(status().isOk)
            .andExpect(header().exists("Authorization"))
            .andDo { result ->
                val authorization = result.response.getHeader("Authorization")
                println("Before Authorization: $jwt") // 세션 ID 출력
                println("Authorization: $authorization") // 세션 ID 출력
            }
    }

    @Test
    fun `인증 요청 실패 - 가짜 JWT`() {
        // 가짜 JWT 발급 (실제 테스트 시에는 로그인 후 JWT를 얻어야 함)
        val jwt = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhcHByb3ZlZF91c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzM1NTk0NTM4LCJleHAiOjE3MzU2ODA5Mzh9.25ZHRNLbDvGXrcAQPRsQRS7Il8w8nsQCFn8wZOAMdSE"

        mockMvc.perform(
            get("/test")
                .header("Authorization", "Bearer $jwt") // JWT 포함
        )
            .andExpect(status().isForbidden)
    }
}
