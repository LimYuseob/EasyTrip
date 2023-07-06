package com.project.easytrip.service;

import com.project.easytrip.dto.SkySearchResultDTO;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.util.List;

@Service
public interface SkyService {

	List<SkySearchResultDTO> getSky(String date, String cabinClass, String adult, String origin, String destination, Model model) throws Exception;
	
	
	
}
