package com.project.easytrip.service;

import com.project.easytrip.dto.MemberAdapter;
import com.project.easytrip.entity.Member;
import com.project.easytrip.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@Service
public class LoginService implements UserDetailsService {

    private final MemberRepository memberRepository;

    private final HttpSession httpSession;

    @Override
    public UserDetails loadUserByUsername(String memberId) throws UsernameNotFoundException {
        //Security 를 통해 로그인 시도
        //DB에 입력한 memberId 값이 있으면 로그인 후 Security 에서 자동으로 인증정보 생성(username&password)
        //메소드 타입을 UserDetails 를 사용하여 UserDetails를 상속받은 MemberAdapter로 DB에 있는 회원정보 반환
        //나중에 MemberAdapter를 이용하여 필요한 페이지에서 바로바로 회원정보 출력
        Member member = memberRepository.findByMemberId(memberId);

        httpSession.setAttribute("member", member);


        return new MemberAdapter(member);
    }
}
