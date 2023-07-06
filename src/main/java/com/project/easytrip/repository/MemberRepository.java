package com.project.easytrip.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.project.easytrip.entity.Member;
import org.springframework.data.jpa.repository.Query;


public interface MemberRepository extends JpaRepository<Member, String> {

	@Query("select m from Member m where m.memberId =:memberId")
	Member findByMemberId(String memberId);

	@Query("select m from Member m where m.memberEmail =:memberEmail")
	Member findByMemberEmail(String memberEmail);


}
