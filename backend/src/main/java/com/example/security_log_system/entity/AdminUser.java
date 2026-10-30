package com.example.security_log_system.entity;


import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.*;


@Entity                     // 이 클래스는 DB 테이블이라고 알려주는 것
@Table(name= "admin_users") // DB에 저장될 테이블 이름
@Getter                     // 모든 필드의 get메서드 자동 생성
@NoArgsConstructor(access = AccessLevel.PROTECTED) // 빈 생성자 만들되 , 외부에서 못 쓰게 막는다.
@AllArgsConstructor         // 모든 필드를 받는 생성자 자동 생성
@Builder                    // 빌더 패턴 사용 가능하게 해줌
public class AdminUser {

    @Id // PK(기본키)
    @GeneratedValue(strategy = GenerationType.IDENTITY) // PK를 DB가 자동으로 1,2,3 증가 시킴
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, length = 20)
    private String role;    // "ROLE_ADMIN"
}

/*
TODO
    - username, role 컬럼명은 괜찮지만 password는 반드시 암호화 저장 보장
    - register API가 테스트용이라면 AdminUser 생성 경로 제한 필요
    - createdAt 같은 계정 생성 시각 컬럼 추가 검토
    - role을 String 대신 Enum으로 관리할지 검토
*/