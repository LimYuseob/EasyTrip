package com.project.easytrip.service;

import com.project.easytrip.dto.MailDTO;
import com.project.easytrip.dto.MemberDTO;
import com.project.easytrip.entity.Member;
import com.project.easytrip.entity.Role;
import com.project.easytrip.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class MemberService{

    @Autowired
    private PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;

    private final MailSender mailSender;



    public Member dtoToEntity(MemberDTO memberDTO){
        //DB에 아이디와 이메일이 있는지 확인후 있다면 Null 없다면 Member.builder() 로 넘어가 회원 정보 생성
        Member byMemberId = memberRepository.findByMemberId(memberDTO.getMemberId());
        Member byMemberEmail = memberRepository.findByMemberEmail(memberDTO.getMemberEmail());
        if(byMemberId != null){

            update(memberDTO);
            return null;

        }else if(byMemberEmail != null){

            update(memberDTO);
            return null;
        }


        Member member = Member.builder()
                .memberId(memberDTO.getMemberId())
                .memberPassword(passwordEncoder.encode(memberDTO.getMemberPassword()))
                .memberName(memberDTO.getMemberName())
                .memberEmail(memberDTO.getMemberEmail())
                .memberPhoneNumber(memberDTO.getMemberPhoneNumber())
                .memberAddress(memberDTO.getMemberAddress())
                .memberDetailAddress(memberDTO.getMemberDetailAddress())
                .role(Role.MEMBER.getValue())
                .build();

        memberRepository.save(member);

        return member;
    }

    public boolean overlappedID(String memberId) {
        Member memberOptional = memberRepository.findByMemberId(memberId);

        if (memberOptional == null) {

            return false;
        }
        return true;
    }

    // Email중복검사
    public boolean overlappedEmail(String memberEmail) {
        Member memberOptional = memberRepository.findByMemberEmail(memberEmail);

        if(memberOptional == null) {

            return false;
        }
        return true;
    }

    @Transactional
    public void update(MemberDTO memberDTO){

        Member member = memberRepository.findByMemberEmail(memberDTO.getMemberEmail());
        member.setMemberId(memberDTO.getMemberId());
        member.setMemberPassword(passwordEncoder.encode(memberDTO.getMemberPassword()));
        member.setMemberName(memberDTO.getMemberName());
        member.setMemberPhoneNumber(memberDTO.getMemberPhoneNumber());
        member.setMemberEmail(memberDTO.getMemberEmail());
        member.setRole(Role.MEMBER.getValue());

        memberRepository.save(member);
    }


    public Member MemberSearch(String memberEmail){

        Member member = memberRepository.findByMemberEmail(memberEmail);

        return member;
    }

    public Member MemberPwSearch(String loginId){


        Member member = memberRepository.findByMemberId(loginId);

        return member;
    }

    // 메일 내용을 생성하고 임시 비밀번호로 회원 비밀번호를 변경
    public MailDTO createMailAndChangePassword(String email){
        String str = getTempPassword();
        MailDTO dto = new MailDTO();
        dto.setAddress(email);
        dto.setTitle("안녕하세요. EasyTrip 입니다. 임시비밀번호 안내 드립니다.");
        dto.setMessage("안녕하세요. EasyTrip 입니다. 임시비밀번호 안내 드립니다. 회원님의 임시 비밀번호는 "
                + str + " 입니다. 로그인 후에 MyPage에서 비밀번호 변경을 해주세요.");
        updatePassword(str,email);
        return dto;
    }

    //임시 비밀번호로 업데이트
    public void updatePassword(String str, String email){
        String memberPassword = str;
        Member member = memberRepository.findByMemberEmail(email);
        member.setMemberPassword(passwordEncoder.encode(memberPassword));
    }

    //랜덤함수로 임시비밀번호 구문 만들기
    public String getTempPassword(){
        char[] charSet = new char[]{'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
                ,'G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};

        String str = "";

        // 문자 배열 길이의 값을 랜덤으로 10개를 뽑아 구문을 작성함
        int idx = 0;
        for (int i = 0; i < 10; i++){
            idx = (int) (charSet.length * Math.random());
            str += charSet[idx];
        }
        return str;

    }

    //메일보내기
    public void mailSend(MailDTO mailDTO){
        System.out.println("임시 비밀번호 메일로 발송 완료");
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(mailDTO.getAddress());
        message.setSubject(mailDTO.getTitle());
        message.setText(mailDTO.getMessage());
        message.setFrom("dladbtjq@naver.com");
        message.setReplyTo("dladbtjq@naver.com");
        System.out.println("message"+message);
        mailSender.send(message);

    }


}
