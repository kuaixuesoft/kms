package com.tuniu.finance.xff.auth.security;

import org.springframework.util.StringUtils;

public class StringMaskUtil {
	public static String mask(String str, int unmaskedHeadLength, int unmaskedTailLength){
		if(StringUtils.isEmpty(str)) return str;
		StringBuilder sb = new StringBuilder();
		for(int i=0; i<str.length(); i++){
			if(i<unmaskedHeadLength)sb.append(str.charAt(i));
			else if(i>=(str.length()-unmaskedTailLength))sb.append(str.charAt(i));
			else sb.append('*');
		}
		return sb.toString();
	}
	
	public static String maskIdNumber(String str){
		return mask(str, 1, 1);
	}
	
	public static String maskBankCard(String str){
		return mask(str, 6, 4);
	}

	public static String maskPhoneNumber(String str){
		return mask(str, 3, 4);
	}
	
	public static String maskName(String str){
		if(StringUtils.isEmpty(str))return str;
		return mask(str, 0, str.length()/2);
	}	
}
