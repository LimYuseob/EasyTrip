package com.project.easytrip.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
	
	USER("ROLE_USER"), ADMIN("ROLE_ADMIN"), MEMBER("ROLE_MEMBER");
	private String value;
	
	Role(String value) {
		this.value = value;
	}
	

}
