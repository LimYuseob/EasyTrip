package com.project.easytrip.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class SkyRerv {

	//예약자 정보 skyAirTicketDTO
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private Long ono;

	private String phone;
	private String userName;
	private String passenger;
	private String dob;
	private String gender;
	private String passport;
	private String nationality;
	
	
	//일정 정보 skyAirTicketDTO
	private String airLine;
	private String logo;
	private String depCode;
	private String depDate;
	private String arrCode;
	private String arrDate;
	private String via;//viaCode + viaDate 합쳐서 저장
	private String duration;
	
	
	
	//결제 정보 kakaoPayApprovalDTO
	private String item_name;
	private int total_price;
	private String payment_type;
	private int quantity;
	private String created_at;
	private String approved_at;
	
	public void changeTitle(String passenger) {
		this.passenger = passenger;
	}

	public void changePassport(String passport) {
		this.passport = passport;
	}
	
	public void changeGender(String gender) {
		this.gender = gender;
	}
	
}
