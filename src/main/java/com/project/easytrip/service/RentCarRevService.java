package com.project.easytrip.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import com.project.easytrip.dto.RentCarRevDTO;
import com.project.easytrip.entity.RentCarRev;

@Service
public interface RentCarRevService {
	
	public List<RentCarRev> SavRentCar(RentCarRev  rentcar);
	List<RentCarRev> getreservation(String reservation);
	
	
	default RentCarRev dtoToEntity(RentCarRevDTO rentcardto) {
		// TODO Auto-generated method stub
		RentCarRev rev	=	RentCarRev.builder()
							.name				(rentcardto.getName())
							.label				(rentcardto.getLabel())
							.dest_type			(rentcardto.getDest_type())
							.pick_up_datetime	(rentcardto.getPick_up_datetime())
							.drop_off_datetime	(rentcardto.getDrop_off_datetime())
							.v_name				(rentcardto.getV_name())
							.seats				(rentcardto.getSeats())
							.fuel_type			(rentcardto.getFuel_type())
							.doors				(rentcardto.getDoors())
							.price				(rentcardto.getPrice())
							.currency			(rentcardto.getCurrency())
							.image_url			(rentcardto.getImage_url())
							.user				(rentcardto.getUser())
							.reservation		(rentcardto.getReservation())
							.build();
		
		return rev;
	}


	
}


