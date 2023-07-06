package com.project.easytrip.entity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.*;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "member")

/**
 * 이 클래스는 회원 정보를 데이터베이스에 저장하는 데 사용되는 엔티티(Entity)입니다.
 * 이 클래스에는 회원 정보와 관련된 필드와 해당 필드에 대한 제약 조건, 회원 가입 날짜를 저장하는 필드가 포함되어 있습니다.
 */
public class Member extends BaseEntity implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long mno;
    private String memberId;

    private String memberPassword;
    private String memberName;
    private String memberEmail;
    private String memberPhoneNumber;
    private String memberAddress;
    private String memberDetailAddress;
    
    private String role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
        auth.add(new SimpleGrantedAuthority(role));
        return auth;
    }

    @Override
    public String getUsername() {
        return memberName;
    }
    @Override
    public String getPassword() {
        return memberPassword;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public Member(String memberId, String memberPassword, String memberName,String memberEmail
            , String memberAddress,String memberDetailAddress,String role){
        this.memberId = memberId;
        this.memberPassword = memberPassword;
        this.memberName = memberName;
        this.memberEmail = memberEmail;
        this.memberAddress = memberAddress;
        this.memberDetailAddress = memberDetailAddress;
        this.role = role;

    }

    public Member update(String memberName){
        this.memberName = memberName;
        return this;
    }


}
