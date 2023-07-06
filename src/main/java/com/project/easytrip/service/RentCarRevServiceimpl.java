package com.project.easytrip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.project.easytrip.entity.RentCarRev;
import com.project.easytrip.repository.RentCarRevRepository;

@Service
public class RentCarRevServiceimpl implements RentCarRevService{
	
	@Autowired
	private RentCarRevRepository	rentcarrevrepository;
	
	
	@Override
	public List<RentCarRev> SavRentCar(RentCarRev rentcar) {
		// TODO Auto-generated method stub
		rentcarrevrepository.save(rentcar);
		
		
		return rentcarrevrepository.findByReservation(rentcar.getReservation());

	}
	
	@Override
	public List<RentCarRev> getreservation(String reservation) {
		// TODO Auto-generated method stub
		return rentcarrevrepository.findByReservation(reservation);
	}

	

	
}
