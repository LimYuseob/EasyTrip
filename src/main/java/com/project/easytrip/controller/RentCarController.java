package com.project.easytrip.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.project.easytrip.dto.RentCarRevDTO;
import com.project.easytrip.entity.RentCarRev;
import com.project.easytrip.service.RentCarRevService;


@Controller
public class RentCarController {
	
	@Autowired
	RentCarRevService	rentcarrevservice;
	
//	
	@GetMapping
	public String loginForm() {
		// Viewer 매핑

		return "CarsRreView";
	}
//	
	@PostMapping("/cars2")
	public String createRentCarRev(@ModelAttribute RentCarRevDTO dto, Model model ){
			//DTO를 Entity로 변환
								
			RentCarRev entity = rentcarrevservice.dtoToEntity(dto);
			
			entity.changeReservation(entity.getUser() + entity.getPick_up_datetime());
			
			List<RentCarRev> rerv = rentcarrevservice.SavRentCar(entity);
			
			model.addAttribute("carRev",rerv);
			return  "/carsrev";
			
	}
	
	
	
}
