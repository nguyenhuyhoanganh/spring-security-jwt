package com.nhha.jwtauthentication.common;

import java.util.Date;

import org.springframework.http.HttpStatus;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class HttpResponse {
	
	private int httpStatusCode;
	
	private HttpStatus httpStatus;
	
	private String reason;
	
	private String message;
	
	private Date timeStamp;
	
	public HttpResponse(int httpStatusCode, HttpStatus httpStatus, String reason, String message) {
		super();
		this.httpStatusCode = httpStatusCode;
		this.httpStatus = httpStatus;
		this.reason = reason;
		this.message = message;
		this.timeStamp = new Date();
	}

}
