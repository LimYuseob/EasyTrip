package com.project.easytrip.controller;

import com.project.easytrip.dto.MailDTO;
import com.project.easytrip.dto.MemberAdapter;
import com.project.easytrip.dto.MemberDTO;
import com.project.easytrip.entity.Member;
import com.project.easytrip.entity.SkyRerv;
import com.project.easytrip.repository.MemberRepository;
import com.project.easytrip.service.MemberService;
import com.project.easytrip.service.SkyRervService;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {

	@Autowired
    private final MemberService memberService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MemberRepository  memberRepository;

    @Autowired
    private SkyRervService skyRervService;


    @GetMapping("/loginPage")
    public String loginPage(){

        return "member/loginpage";
    }



    @GetMapping("/signup")
    public String signUp(){
        return "member/signup";
    }

    @PostMapping("/signup")
    public String join(MemberDTO memberDTO){

        memberService.dtoToEntity(memberDTO);

        return "redirect:/member/loginPage";

    }

    // 아이디 중복검사
    @GetMapping("/idCheck")
    @ResponseBody
    public ResponseEntity<?> overlappedID(@RequestParam String id) {
        boolean isOverlapped = memberService.overlappedID(id);
        return ResponseEntity.ok(isOverlapped);
    }

    // 이메일 중복검사
    @GetMapping("/emailCheck")
    @ResponseBody
    public ResponseEntity<?> overlappedEmail(@RequestParam String email) {
        boolean isOverlapped = memberService.overlappedEmail(email);
        return ResponseEntity.ok(isOverlapped);
    }

    @GetMapping("/myPage")
    public String getMyPage(Model model, HttpServletRequest request) {

        HttpSession session = request.getSession();


        if(session == null){

            return "redirect:/";

        } else if (session.getAttribute("member") == null) {
            Member member = (Member) session.getAttribute("SNSmember");
            model.addAttribute("member", member);
            return "member/mypage";
        }

        Member member = (Member) session.getAttribute("member");

        model.addAttribute("member", member);


        return "member/mypage";
    }

    @ResponseBody
    @PostMapping("/mypage")
    public String update(@ModelAttribute MemberDTO memberDTO) {

        String message = "";
        // 받아온 회원 정보를 업데이트 합니다.
        memberService.update(memberDTO);


        // 업데이트된 회원의 상세 정보 페이지로 리다이렉트 합니다.
        message = "<script>alert('회원 정보가 수정되었습니다 다시 로그인 하세요!');location.href='/member/logout';</script>";
        return message;
    }
    @GetMapping("/updatePassword")
    public String updatePassword(@AuthenticationPrincipal MemberAdapter memberAdapter, Model model) {
        // 현재 세션에 저장된 "loginId" 속성 값을 가져와 myId 변수에 저장합니다.
        Member member = memberAdapter.getMember();

        model.addAttribute("member", member);

        return "member/updatePassword";
    }

    @GetMapping("/reservation")
    private String getReservation(Model model,HttpServletRequest request) {

        HttpSession session = request.getSession();

        String name = "";
        String phone = "";

        if(session == null) {

            return "redirect:/member/myPage";

        }else if(session.getAttribute("member") == null) {

            Member member = (Member) session.getAttribute("SNSmember");

            name = member.getMemberName();
            phone = member.getMemberPhoneNumber();

            System.out.println(name+phone+"++++++++++++++++++++++++");

            List<SkyRerv> rerv = skyRervService.getPassenger(name, phone, model);

            model.addAttribute("member", member);
            model.addAttribute("reservationList", rerv);

            System.out.println("check-=-=-=-" + name + " " + phone);

            return "member/reservation";

        }

        Member member = (Member) session.getAttribute("member");

        name = member.getMemberName();
        phone = member.getMemberPhoneNumber();
        System.out.println(name+phone+"++++++++++++++++++++++++2222222222222222222");

        System.out.println("check-=-=-=-" + name + " " + phone);

        List<SkyRerv> rerv = skyRervService.getPassenger(name, phone, model);

        model.addAttribute("member", member);
        model.addAttribute("reservationList", rerv);

        return "member/reservation";
    }

    @GetMapping("/SearchId")
    public String SearchId() {


        return "member/SearchId";
    }

    @PostMapping("/SearchId")
    public String SearchIdFinal(MemberDTO memberDTO, Model model) {

        int errorMsg = 0;
        Member member = memberService.MemberSearch(memberDTO.getMemberEmail());
        model.addAttribute("member",member);
        if(member == null) {
            errorMsg = 1;
            model.addAttribute("errorMsg",errorMsg);

            return "member/SearchId";
        }else if(member.getMemberEmail().equals(memberDTO.getMemberEmail())){

            return "member/SearchIdFinal";
        }
        return null;
    }


    @GetMapping("/SearchPw")
    public String getSearchPw(){

        return "member/SearchPw";
    }

    @Transactional
    @PostMapping("/SearchPw")
    public String SearchPw(MemberDTO memberDTO, Model model){

        int errMsg = 0;

        Member member = memberService.MemberPwSearch(memberDTO.getMemberId());

        if(member == null){
            errMsg = 1;
            model.addAttribute("errMsg", errMsg);

            return "member/SearchPw";

        } else if (!member.getMemberEmail().equals(memberDTO.getMemberEmail())) {
            errMsg  = 2;
            model.addAttribute("errMsg", errMsg);

            return "member/SearchPw";
        }

        MailDTO dto = memberService.createMailAndChangePassword(memberDTO.getMemberEmail());
        memberService.mailSend(dto);

        return "redirect:/";
    }

}
