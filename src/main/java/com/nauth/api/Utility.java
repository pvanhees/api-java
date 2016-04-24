package com.nauth.api;

import java.util.Base64;


class Utility {
	public static String base64encode(byte [] data){
		if(data == null)
			return null;
		return new String(Base64.getEncoder().encode(data));
	}
	
	public static byte[] base64decode(String data){
		if(data == null)
			return null;
		return Base64.getDecoder().decode(data);
	}
	
}
