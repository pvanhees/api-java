package com.nauth.api;

import java.io.IOException;

import com.nauth.api.Base64;

class Utility {
	public static String base64encode(byte [] data){
		if(data == null)
			return null;
		
		return new String(Base64.encodeBytes(data));
	}
	
	public static byte[] base64decode(String data){
		if(data == null)
			return null;
		try {
			return Base64.decode(data.getBytes());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return new byte[0];
		}
	}
	
}
