package com.project.easytrip.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.context.annotation.EnableLoadTimeWeaving;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SkySearchResultDTO {

	private String logo;
	private String name;
	private String price;
	private String duration;
	private String depDate;
	private String depCode;
	private String arrDate;
	private String viaDateTime;
	private String arrCode;
	private String viaCode;

//	private String airLineName;
//	private String logo;
//	private String price;
//	private String duration;
//	private String depDate;
//	private String depCode;
//	private String arrDate;
//	private String arrCode;
//	private String viaCode;
//	private String viaDateTime;
	
}

