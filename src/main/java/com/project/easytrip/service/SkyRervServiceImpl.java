package com.project.easytrip.service;

import com.project.easytrip.dto.KakaoPayApprovalDTO;
import com.project.easytrip.dto.ModifyDTO;
import com.project.easytrip.dto.SkyAirTicketDTO;
import com.project.easytrip.dto.SkyAirTicketRoundDTO;
import com.project.easytrip.entity.SkyRerv;
import com.project.easytrip.repository.SkyRervRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.util.List;
import java.util.Optional;

@Service
public class SkyRervServiceImpl implements SkyRervService{

	@Autowired
	private SkyRervRepository skyRervRepository;

	@Override
	public void getRerv(SkyAirTicketDTO skaDto, KakaoPayApprovalDTO kpaDto) {
		// TODO Auto-generated method stub
		SkyRerv rerv = dtoToEntity(skaDto, kpaDto);
		skyRervRepository.save(rerv);
	}

	@Override
	public void rerv(SkyAirTicketRoundDTO sat, KakaoPayApprovalDTO kpa) {
		double a = Double.parseDouble(sat.getPrice()) * 1300;
		double b = Double.parseDouble(sat.getPrice2()) * 1300;
		int sum = (int) ((int) a + b);

		SkyRerv rerv1 = SkyRerv.builder()
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
				.payment_type(kpa.getPayment_method_type())
				.quantity(kpa.getQuantity())
				.created_at(String.valueOf(kpa.getCreated_at()))
				.approved_at(String.valueOf(kpa.getApproved_at()))
				.item_name(kpa.getItem_name())
				.phone(sat.getPhone())
				.build();


		SkyRerv rerv2 = SkyRerv.builder()
				.passenger(sat.getUser())
				.dob(sat.getDob())
				.gender(sat.getGender())
				.passport(sat.getPassport())
				.nationality(sat.getNationality())
				.airLine(sat.getName2())
				.logo(sat.getLogo2())
				.depCode(sat.getDepCode2())
				.depDate(sat.getDepDate2())
				.arrCode(sat.getArrCode2())
				.arrDate(sat.getArrDate2())
				.via(sat.getViaCode2()+":"+sat.getViaDateTime2())
				.duration(sat.getDuration2())
				.total_price(sum)
				.payment_type("카드")
				.quantity(2)
				.created_at("String.valueOf(kpa.getCreated_at())")
				.approved_at("String.valueOf(kpa.getApproved_at())")
				.item_name("test")
				.phone(sat.getPhone())
				.build();

		skyRervRepository.save(rerv1);
		skyRervRepository.save(rerv2);
	}

	@Override
	public List<SkyRerv> getPassenger(String userName, String passport, Model model) {

		List<SkyRerv> rerv = skyRervRepository.findByPassengerAndPhone(userName, passport);

		return rerv;

	}

	@Override
	public SkyRerv getReservation(Long ono) {
		Optional<SkyRerv> optionalReservation = skyRervRepository.findById(ono);

	    if (optionalReservation.isPresent()) {
	        return optionalReservation.get();
	    } else {
	        // 예외 처리 (예약 정보를 찾을 수 없는 경우 등)
	        return null;
	    }
	}

	@Override
	public void remove(Long id) {
		// TODO Auto-generated method stub
		skyRervRepository.deleteById(id);

	}

	@Override
	public void modify(ModifyDTO dto) {
		// TODO Auto-generated method stub
		SkyRerv rerv = skyRervRepository.getOne(dto.getId());

		rerv.changeTitle(dto.getUserName());
		rerv.changePassport(dto.getPassport());
		rerv.changeGender(dto.getGender());
		System.out.println("rerv 수정내용"+rerv);
		skyRervRepository.save(rerv);

	}

	
}
