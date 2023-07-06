package com.project.easytrip.service;

import com.project.easytrip.dto.KakaoPayApprovalDTO;
import com.project.easytrip.dto.ModifyDTO;
import com.project.easytrip.dto.SkyAirTicketDTO;
import com.project.easytrip.dto.SkyAirTicketRoundDTO;
import com.project.easytrip.entity.Member;
import com.project.easytrip.entity.SkyRerv;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.Locale;

@Service
public interface SkyRervService {
	
	public void getRerv(SkyAirTicketDTO skaDto, KakaoPayApprovalDTO kpaDto);

	void rerv(SkyAirTicketRoundDTO dto, KakaoPayApprovalDTO kpa);

	List<SkyRerv> getPassenger(String userName, String phone, Model model);

	SkyRerv getReservation(Long ono);

	void remove(Long ono);

	void modify(ModifyDTO dto);
	
	default SkyAirTicketDTO entityToSkaDto(SkyRerv rerv) {

		SkyAirTicketDTO skaDTO = SkyAirTicketDTO.builder()
								.logo(rerv.getLogo())
								.duration(rerv.getDuration())
								.depCode(rerv.getDepCode())
								.depDate(rerv.getDepDate())
								.arrCode(rerv.getArrCode())
								.arrDate(rerv.getArrDate())
								.name(rerv.getAirLine())
								.viaCode(rerv.getVia())
								.build();

		return skaDTO;

	}
	
	default KakaoPayApprovalDTO entityToKpaDto(SkyRerv rerv) {

		String createdDateString = rerv.getCreated_at(); // 기존 문자열 날짜
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH); // 변환할 포맷 지정
		ZonedDateTime zonedDateTime = ZonedDateTime.parse(createdDateString, formatter); // 문자열을 ZonedDateTime으로 변환
		Date cre_at = Date.from(zonedDateTime.toInstant()); // ZonedDateTime을 Date로 변환

		String approveDateString = rerv.getApproved_at(); // 기존 문자열 날짜
		ZonedDateTime zonedDateTime2 = ZonedDateTime.parse(approveDateString, formatter); // 문자열을 ZonedDateTime으로 변환
		Date app_at = Date.from(zonedDateTime2.toInstant()); // ZonedDateTime을 Date로 변환

		KakaoPayApprovalDTO kpaDTO = KakaoPayApprovalDTO.builder()
									.total_price(rerv.getTotal_price())
									.item_name(rerv.getItem_name())
									.created_at(cre_at)
									.approved_at(app_at)
									.quantity(rerv.getQuantity())
									.payment_method_type(rerv.getPayment_type())
									.build();

		return kpaDTO;

	}


	default SkyRerv dtoToEntity(SkyAirTicketDTO sat, KakaoPayApprovalDTO kpa) {
		SkyRerv rerv = SkyRerv.builder()
						.passenger(sat.getUser())
						.dob(sat.getDob())
						.gender(sat.getGender())
						.passport(sat.getPassport())
						.nationality(sat.getNationality())
						.airLine(sat.getName())
						.logo(sat.getLogo())
						.depCode(sat.getDepCode())
						.depDate(sat.getDepDate())
						.arrCode(sat.getArrCode())
						.arrDate(sat.getArrDate())
						.via(sat.getViaCode()+":"+sat.getViaDateTime())
						.duration(sat.getDuration())
						.total_price(kpa.getAmount().getTotal())
						.payment_type(kpa.getPayment_method_type())
						.quantity(kpa.getQuantity())
						.created_at(String.valueOf(kpa.getCreated_at()))
						.approved_at(String.valueOf(kpa.getApproved_at()))
						.item_name(kpa.getItem_name())
						.phone(sat.getPhone())
						.build();
		return rerv;
	}
	default SkyRerv dtoToEntity_test(SkyAirTicketRoundDTO sat){

		int a = Integer.parseInt(sat.getPrice());
		int b = Integer.parseInt(sat.getPrice2());
		int sum = a + b;

		SkyRerv rerv = SkyRerv.builder()
				.passenger(sat.getUser())
				.dob(sat.getDob())
				.gender(sat.getGender())
				.passport(sat.getPassport())
				.nationality(sat.getNationality())
				.airLine(sat.getName())
				.logo(sat.getLogo())
				.depCode(sat.getDepCode())
				.depDate(sat.getDepDate())
				.arrCode(sat.getArrCode())
				.arrDate(sat.getArrDate())
				.via(sat.getViaCode()+":"+sat.getViaDateTime())
				.duration(sat.getDuration())
				.total_price(sum)
				.payment_type("카드")
				.quantity(2)
				.created_at("String.valueOf(kpa.getCreated_at())")
				.approved_at("String.valueOf(kpa.getApproved_at())")
				.item_name("test")
				.build();

		return rerv;

	}
}
