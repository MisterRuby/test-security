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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.transaction.annotation.Transactional
import ruby.commonsecurity.domain.*

@SpringBootTest(classes = [AuthLibraryConfig::class])
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
}
