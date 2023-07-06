package com.project.easytrip.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.project.easytrip.dto.*;
import com.project.easytrip.entity.SkyRerv;
import com.project.easytrip.service.KakaoPayService;
import com.project.easytrip.service.SkyRervService;
import com.project.easytrip.service.SkyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Controller
@RequestMapping("/flight")
public class SkyController {

	@Autowired
	private SkyService skyService;

	@Autowired
	private SkyRervService skyRervService;

	@Autowired
	private KakaoPayService kakaoPayService;

	@GetMapping("/skySearch")
	private String skySearch() {

		return "/flight/skySearch";

	}

	@GetMapping("/skyResult")
	public String result(){
		return "/flight/one_way";
	}

	@GetMapping("/round2")
	public String round2(@ModelAttribute SkySearchResultDTO data, Model model, HttpSession session) throws Exception {

		System.out.println("dto확인=="+data.toString());

		session.setAttribute("first", data);


//		DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
//
//		String date = (String) session.getAttribute("arrivalDate");
//
//		Date d = df.parse(date);
//		date = df.format(d);
//		List<SkySearchResultDTO> list = skyService.getSky(date, (String) session.getAttribute("cabinClass"),
//				(String) session.getAttribute("adult"),
//				(String) session.getAttribute("origin"),
//				(String) session.getAttribute("destination"),model);

		List<SkySearchResultDTO> list = new ArrayList<>();
		SkySearchResultDTO dto = SkySearchResultDTO.builder()
				.name("아시아나")
				.depCode("ICN")
				.depDate("2023-06-14")
				.arrCode("OSK")
				.arrDate("2023-06-15")
				.duration("12H")
				.logo("2000")
				.price("220")
				.viaCode("직항")
				.viaDateTime("2023-06-13")
				.build();

		list.add(dto);
		System.out.println("list------->"+ list);

		model.addAttribute("sky", list);

		return "/flight/round2";
	}


	@GetMapping("/skyPaymentRoundTrip")
	public String paasd(@ModelAttribute SkySearchResultDTO data,Model model, HttpSession session){
		List<SkySearchResultDTO> first = new ArrayList<>();
		first.add((SkySearchResultDTO) session.getAttribute("first"));
		model.addAttribute("first", first);
		model.addAttribute("second", data);


		return "/flight/skyPaymentRoundTrip";
	}


	@GetMapping("/round")
	private String round_trip(@RequestParam("departureDate") String date,
							  @RequestParam("cabinClass") String cabinClass,
							  @RequestParam("adults") String adult,
							  @RequestParam("origin") String origin,
							  @RequestParam("destination") String destination,
							  @RequestParam("arrivalDate") String arrival,
							  Model model, HttpSession session) throws Exception {

		session.setAttribute("cabinClass",cabinClass);
		session.setAttribute("adult",adult);
		session.setAttribute("origin",destination);
		session.setAttribute("destination",origin);
		session.setAttribute("arrivalDate",arrival);

		DateFormat df = new SimpleDateFormat("yyyy-MM-dd");

		Date d = df.parse(date);
		date = df.format(d);
		List<SkySearchResultDTO> list = skyService.getSky(date, cabinClass, adult, origin, destination, model);
		System.out.println("list------->"+ list);
		model.addAttribute("sky", list);


		return "/flight/round";


	}

	@GetMapping("/one_way")
	private String one_way(@RequestParam("departureDate") String date,
						   @RequestParam("cabinClass") String cabinClass,
						   @RequestParam("adults") String adult,
						   @RequestParam("origin") String origin,
						   @RequestParam("destination") String destination,
						   Model model) throws Exception {

		System.out.println(date + " 데이트 " + cabinClass + " 좌석 " + adult + " 명수 " + origin + " 출발 " + destination);

		DateFormat df = new SimpleDateFormat("yyyy-MM-dd");

		Date d = df.parse(date);
		date = df.format(d);
		List<SkySearchResultDTO> list = skyService.getSky(date, cabinClass, adult, origin, destination, model);

		System.out.println("list------->"+ list);
		model.addAttribute("sky", list);

		return "/flight/one_way";
	}


	@GetMapping("/skyPayment")
	private void pay() {
		// TODO Auto-generated method stub
	}

	@GetMapping("/kakaoPay")
	public String payGet(@ModelAttribute SkyAirTicketDTO dto, HttpSession session) throws JsonProcessingException {

		session.setAttribute("getsession", dto);
		String url = kakaoPayService.kakaoPayReady(dto);
		return "redirect:"+url;
	}

	@GetMapping("/kakaoPayRound")
	public String payG(@ModelAttribute SkyAirTicketRoundDTO dto2, HttpSession session) throws JsonProcessingException {
		System.out.println("바인딩 확인---"+dto2);
		String url = kakaoPayService.kakaoPayReadyRound(dto2);
		session.setAttribute("getsession2",dto2);

		return "redirect:"+url;
	}


	@GetMapping("/kakaoPaySuccess")
    public String kakaoPaySuccess(@RequestParam("pg_token") String pg_token, HttpSession session, Model model) {
		KakaoPayApprovalDTO kDto = kakaoPayService.kakaoPayInfo(pg_token);
		int getTotal = kDto.getAmount().getTotal();
		kDto.setTotal_price(getTotal);

		List list = new ArrayList<>();
		if(session.getAttribute("first") == null){

			System.out.println("first == null");
			SkyAirTicketDTO dto = (SkyAirTicketDTO) session.getAttribute("getsession");
			list.add(dto);
			skyRervService.getRerv(dto, kDto);
			model.addAttribute("payinfo", kDto);
			model.addAttribute("info", list);
			return "/flight/kakaoPaySuccess";

		}else if(session.getAttribute("first") != null){

			System.out.println("first != NULL");
			SkyAirTicketRoundDTO dto2 = (SkyAirTicketRoundDTO) session.getAttribute("getsession2");
			list.add(dto2);
			model.addAttribute("payinfo", kDto);
			model.addAttribute("info", list);
			skyRervService.rerv(dto2, kDto);
			return "/flight/kakaoPaySuccessRound";
		}


		return null;
    }

	@GetMapping("/reservation")
	public String selectPassenger(@RequestParam("name") String name, @RequestParam("phone") String phone, Model model) {

		List<SkyRerv> rerv = skyRervService.getPassenger(name, phone, model);

		model.addAttribute("reservationList", rerv);

		return  "flight/reservation";

	}

	@GetMapping("/detail")
	public String showDetail(@RequestParam("id") Long id, Model model) {

		System.out.println("id--"+id);
		SkyRerv reservation = skyRervService.getReservation(id);
		model.addAttribute("reservation", reservation);

		return "/flight/detail";

	}

	@PostMapping("/rervRemove")
	public String remove(Long id) {

		skyRervService.remove(id);

		return "redirect:/member/mypage";
	}

	@PostMapping("/update")
	public String modify(@ModelAttribute ModifyDTO dto) {
		System.out.println("update호출");
		skyRervService.modify(dto);

		return "redirect:/member/mypage";
	}

	@GetMapping("/redirect1")
	public String redirect1(Model model) {

		return "redirect:/flight";
	}

	@GetMapping("/search")
	public void passSearch() {

	}

}
