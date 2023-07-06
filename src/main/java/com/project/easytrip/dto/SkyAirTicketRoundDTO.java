package com.project.easytrip.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SkyAirTicketRoundDTO {

	private int adults;
	private String logo;
    private String price;
    private String duration;
    private String depCode;
    private String depDate;
    private String arrCode;
    private String arrDate;
    private String name; //항공사 이름
    private String viaCode;
    private String viaDateTime;
    private String user; //에약자 이름
    private String dob; //생년월일
    private String gender;
    private String passport;
    private String nationality;
    private String phone;

    private String logo2;
    private String price2;
    private String duration2;
    private String depCode2;
    private String depDate2;
    private String arrCode2;
    private String arrDate2;
    private String name2; //항공사 이름
    private String viaCode2;
    private String viaDateTime2;
  
 
	
}



