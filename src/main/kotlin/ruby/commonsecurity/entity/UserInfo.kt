package ruby.commonsecurity.entity

import jakarta.persistence.*
import org.springframework.data.jpa.repository.JpaRepository
import java.time.LocalDateTime

@Entity
data class UserInfo(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    @Column(nullable = false, unique = true)
    val email: String,

    @Column(nullable = false)
    val password: String,

    @Column(nullable = false)
    val name: String,

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    val accountStatus: AccountStatus,

    @Column(nullable = false)
    val createdDate: LocalDateTime = LocalDateTime.now(),

    @Column(nullable = false)
    var modifiedDate: LocalDateTime = LocalDateTime.now()
)

enum class AccountStatus {
    APPROVED, REJECTED, PENDING, SUSPENDED, DEACTIVATED
}

interface UserInfoRepository : JpaRepository<UserInfo, Long> {
    fun findByEmail(email: String): UserInfo?
}
