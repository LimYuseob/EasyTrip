package com.project.easytrip.entity;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.springframework.context.annotation.Primary;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data

public class RentCarRev {

	@Id
	private	String	reservation;			//렌터카예약번호
	
	private	String	name;						//대여장소
	private String	label;						//대여상세
	private String	dest_type;					//대여장소 구분(도시:city, 지역:district, 장소:landmark, 공항:airport)
	private String	pick_up_datetime;			//대여일시
	private String	drop_off_datetime;			//반납일시
	private String	v_name;						//차종명
	private String	seats;						//의자수
	private String	fuel_type;					//연료구분
	private String	doors;						//문짝갯수
	private String	price;						//대여금액
	private String	currency;					//화폐단위
	private String	image_url;					//이미지URL
	private String 	user;
	
	
	
	public void changeUser(String user) {
		this.user	=	user;
	}

	public void changeReservation(String reservation) {
		this.reservation = reservation;
	}
	
}
