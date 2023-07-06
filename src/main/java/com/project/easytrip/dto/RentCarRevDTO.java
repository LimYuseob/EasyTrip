package com.project.easytrip.dto;

public class RentCarRevDTO {
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
	private String	user;					//아이디
	
	
	
	public String getReservation() {
		return reservation;
	}
	public void setReservation(String reservation_num) {
		this.reservation = reservation_num;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getLabel() {
		return label;
	}
	public void setLabel(String label) {
		this.label = label;
	}
	public String getDest_type() {
		return dest_type;
	}
	public void setDest_type(String dest_type) {
		this.dest_type = dest_type;
	}
	public String getPick_up_datetime() {
		return pick_up_datetime;
	}
	public void setPick_up_datetime(String pick_up_datetime) {
		this.pick_up_datetime = pick_up_datetime;
	}
	public String getDrop_off_datetime() {
		return drop_off_datetime;
	}
	public void setDrop_off_datetime(String drop_off_datetime) {
		this.drop_off_datetime = drop_off_datetime;
	}
	public String getV_name() {
		return v_name;
	}
	public void setV_name(String v_name) {
		this.v_name = v_name;
	}
	public String getSeats() {
		return seats;
	}
	public void setSeats(String seats) {
		this.seats = seats;
	}
	public String getFuel_type() {
		return fuel_type;
	}
	public void setFuel_type(String fuel_type) {
		this.fuel_type = fuel_type;
	}
	public String getDoors() {
		return doors;
	}
	public void setDoors(String doors) {
		this.doors = doors;
	}
	public String getPrice() {
		return price;
	}
	public void setPrice(String price) {
		this.price = price;
	}
	public String getCurrency() {
		return currency;
	}
	public void setCurrency(String currency) {
		this.currency = currency;
	}
	public String getImage_url() {
		return image_url;
	}
	public void setImage_url(String image_url) {
		this.image_url = image_url;
	}
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	
	
}
