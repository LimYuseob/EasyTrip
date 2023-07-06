package com.project.easytrip.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.project.easytrip.entity.RentCarRev;


public interface RentCarRevRepository extends JpaRepository<RentCarRev, String> {
	//RentCarRevList 전체를 리턴하는 메서드쿼리 이용
	//List<RentCarRev> findByUser_id(String user_id);
//	List<RentCarRev> findByUser(String user);
	List<RentCarRev> findByReservation(String reservation);

}
