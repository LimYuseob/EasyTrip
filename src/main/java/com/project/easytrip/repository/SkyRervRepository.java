package com.project.easytrip.repository;


import com.project.easytrip.entity.SkyRerv;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SkyRervRepository extends JpaRepository<SkyRerv, Long> {

	 List<SkyRerv> findByPassengerAndPhone(String userName, String phone);
	 
	 
}
