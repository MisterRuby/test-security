package ruby.testsecurity.domain

import jakarta.persistence.*
import org.springframework.data.jpa.repository.JpaRepository

@Entity
data class Company(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    @Column(nullable = false)
    val name: String,

    @Column(nullable = false, unique = true)
    val registrationNumber: String,

    @Column(nullable = false)
    val address: String
)

interface CompanyRepository : JpaRepository<Company, Long>