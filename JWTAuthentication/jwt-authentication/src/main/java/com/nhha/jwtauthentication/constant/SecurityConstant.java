package com.nhha.jwtauthentication.constant;

public class SecurityConstant {
	public static final long EXPIRATION_TIME = 432_000_000; // 5 days
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String JWT_TOKEN_HEADER = "Jwt-token";
	public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
	public static final String GET_ARRAYS_LCC = "Get Arrays, LCC";
	public static final String GET_ARRAYS_ADMINISTATION = "User Mangement Portal";
	public static final String AUTHORITIES = "authorities";
	public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page";
	public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
	public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
	public static final String[] PUBLIC_URLS = { "/user/login", "/user/register", "/user/resetpassword/**",
			"/user/image/**" };
}
