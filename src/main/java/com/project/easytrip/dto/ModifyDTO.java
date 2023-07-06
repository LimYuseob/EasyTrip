package com.project.easytrip.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ModifyDTO {

	private Long id;
	private String userName;
	private String gender;
	private String passport;
	
}
