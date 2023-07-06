package com.project.easytrip.dto;

import lombok.Data;
import lombok.ToString;

import java.util.Date;

@Data
@ToString
public class KakaoPayReadyDTO {//결제 요청 시 카카오에게 받음

	   private String tid, next_redirect_pc_url;
	   private Date created_at;
	    
	
}
