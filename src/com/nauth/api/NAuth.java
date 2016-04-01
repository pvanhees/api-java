package com.nauth.api;

import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class NAuth {
	public String getServeruri() {
		return serveruri;
	}


	public void setServeruri(String serveruri) {
		this.serveruri = serveruri;
	}


	public String getRealm() {
		return realm;
	}


	public void setRealm(String realm) {
		this.realm = realm;
	}


	public String getId() {
		return sid;
	}
	
	public String getHashId(){
		if($hsid == null){
			login_forcecheck();
			return $hsid;
		} else {
			return $hsid;
		}
	}


	public void setId(String sid) {
		this.sid = sid;
	}


	public String getServerid() {
		return serverid;
	}


	public void setServerid(String serverid) {
		this.serverid = serverid;
	}


	public String getApikey() {
		return apikey;
	}


	public void setApikey(String apikey) {
		this.apikey = apikey;
	}


	public String getWsuri() {
		return wsuri;
	}


	public void setWsuri(String wsuri) {
		this.wsuri = wsuri;
	}


	public String getFallbackwsuri() {
		return fallbackwsuri;
	}


	public void setFallbackwsuri(String fallbackwsuri) {
		this.fallbackwsuri = fallbackwsuri;
	}


	private String serveruri = "http://localhost:8888/";
	private String realm = "";
	private String sid = "";
	private String serverid = "";
	private String apikey = "";
	private NAuthBackend backend;
	private String wsuri;
	private String fallbackwsuri;

		
	/* temporary caching */
	private String $userid;
	private String $userpk;
	private Boolean $loggedin = null;
	private Boolean $canprovoke = null;
	private String $loginqrdata = null;
	private String $hsid = null;
	
	
	public NAuth(String serverid, String apikey){
		setServerid(serverid);
		setApikey(apikey);
		
		backend = new NAuthBackend(true);
	}
	
	protected String serverGet(String method, String[] queryParts, Map<String,String> params){
		return backend.getHttpAsString(method, getServeruri(),queryParts,params,getHeaders());
	}
	
	protected byte [] serverGetBytes(String method, String[] queryParts, Map<String,String> params){
		return backend.getHttpAsBytes(method, getServeruri(),queryParts,params,getHeaders());
	}
	
	
	
	/**
	 * Logout the current NAuth session
	 */
	public void logout(){
		
		serverGet("POST", new String[] {"servers",getServerid(),"sessions",getId(),"logout"}, null);
	}
	
	private Map<String,String> getHeaders(){
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("apikey", getApikey());
		return headers;
	}
 	
	private JSONObject sessionCheck(){
		Map<String, String> params = new HashMap<String, String>();
		params.put("realm", getRealm());
		
		JSONParser parser = new JSONParser();
		try {
			return (JSONObject) parser.parse(serverGet("GET", 
					new String[]{"servers",getServerid(),"sessions",getId()}, params));
		} catch (ParseException e) {
			return null;
		}
	}
	
	/**
	 * Check if the user is logged in.
	 * Note that this method might used a cached result. 
	 * Caching happens automatically in an NAuth object, but are not stored in the session or shared otherwise over multiple requests.
	 * 
	 * @return boolean True if the user is logged in through NAuth
	 */
	public boolean login(){
		if($loggedin == null){
			return login_forcecheck();
		} else {
			return $loggedin;
		}
	}
	
	/**
	 * Check if the user is logged in.
	 * This method never uses caching and has an impact on performance.
	 *
	 * @return boolean True if the user is logged in through NAuth
	 */
	public boolean login_forcecheck() {
		$loggedin = false;
		
		JSONObject loginData = sessionCheck();
		if(((Boolean) loginData.get("loggedin")) != false){
			$userpk  = (String) loginData.get("pk");
			$userid  = (String) loginData.get("userid");
			$loggedin = true;
			$canprovoke = (Boolean) loginData.get("canprovoke");
			$loginqrdata = (String) loginData.get("loginqrdata");
			$hsid = (String) loginData.get("hsid");
			return true;
		} else {
			$canprovoke = (Boolean) loginData.get("canprovoke");
			$loginqrdata = (String) loginData.get("loginqrdata");
			$hsid = (String) loginData.get("hsid");
			return false;
		}
	}
	
	/**
	 * Register a userId for the currently logged in session
	 * 
	 * @param string $userid Userid
	 * @return boolean True on success
	 */
	public boolean registerUser(String userid){
		if(!login())
			return false;
		
		Map<String, String> params = new HashMap<String, String>();
		params.put("realm", getRealm());
		params.put("userid", userid);
		
		serverGet("POST",
				new String[]{"servers",getServerid(),"sessions",getId(),"registeruser"}, params);
		return true;
	}
	
	/**
	 * Get the userid of the currently logged in user.
	 * 
	 * @return string The userid or false on failure.
	 */
	public String getUserId(){
		if($loggedin)
			return $userid;
		return null;
	}
	
	/**
	 * Synonym for login()
	 * 
	 * @return boolean True if the user is logged in through NAuth
	 */
	public boolean loggedin(){
		return login();
	}
	
	/**
	 * Get the public key of the currently logged in user
	 * 
	 * @return string Base64 encoded public key
	 */
	public String getUserpk() {
		if($loggedin)
			return $userpk;
		return null;
	}
	
	/**
	 * Return the raw data that is usually represented in a visual code for login/enrol.
	 * 
	 * @param string $type Type of code (either "LOGIN" or "ENROL")
	 * @param string $name Display name to register for the user (only for ENROL)
	 * @param string $userid Userid to register for the user (only for ENROL)
	 */
	public String getbase64qrcodedata(String type){
		return getbase64qrcodedata(type,"","");
	}
	public String getbase64qrcodedata(String type, String name){
		return getbase64qrcodedata(type,name,"");
	}
	
	public String getbase64qrcodedata(String type, String name, String userid) {
		/* caching is enabled for LOGIN code (this is already passed when doing a validate */
		if("LOGIN".equals(type)){
			if($loginqrdata != null){
				return $loginqrdata;
			} else {
				login_forcecheck();
				return $loginqrdata;
			} 
		}
		
		Map<String, String> params = new HashMap<String, String>();
		params.put("realm", getRealm());
		params.put("userid", userid);
		params.put("type", type);
		params.put("name", name);
		
		return serverGet("GET", new String[]{"servers",getServerid(),"sessions",getId(),"qr"}, params);
	}
	
	
	/**
	 * Returns a PNG image of the visual login/enrol code 
	 * 
	 * @param string $type		Type of code (either "LOGIN" or "ENROL")
	 * @param string $imgtype	Type of image (either "nauth" or "qr")
	 * @param number $size		Size of the image in pixels
	 * @param string $name		Display name to register for the user (only for ENROL)
	 * @param string $userid	Userid to register for the user (only for ENROL)
	 * @return Raw PNG data
	 */
	public byte [] getqrcodeimgdata(String type, String imgtype, int size, String name, String userid) {
		if(!"nauth".equals(imgtype) && !"qr".equals(imgtype))
			imgtype = "qr";
		
		Map<String, String> params = new HashMap<String, String>();
		params.put("realm", getRealm());
		params.put("userid", userid);
		params.put("type", type);
		params.put("name", name);
		params.put("s", ""+size);
		params.put("img",imgtype);
		
		return serverGetBytes("GET", new String[]{"servers",getServerid(),"sessions",getId(),"qr"}, params);
	}
	public byte [] getqrcodeimgdata(String type, String imgtype, int size) {
		return getqrcodeimgdata(type, imgtype, size, "","");
	}
	
	/**
	 * Provoke a login for the current user
	 * @return boolean True on success
	 */
	public boolean provokelogin(){
		String result = serverGet("POST",new String[]{"servers",getServerid(),"sessions",getId(),"provokelogin"},null);
		JSONParser parser = new JSONParser();
		try {
			JSONObject obj = (JSONObject) parser.parse(result);
			Boolean ret = (Boolean) obj.get("result");
			return ret;
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	}
	
	/**
	 * Check if a login can be provoked from the server
	 * 
	 * @return boolean True if provoke is possible
	 */
	public boolean canProvoke() {
		if($canprovoke != null){
			return $canprovoke;
		} else {
			login_forcecheck();
			return $canprovoke;
		}
	}
	
	/**
	 * Create a new transaction with the specified message
	 * 
	 * @param string $msg 	Message for the transaction
	 * @return string 		Base64 encoded transaction identifier
	 */
	public String createTransaction(String msg){
		Map<String, String> params = new HashMap<String, String>();
		params.put("msg", msg);
		
		String result  = serverGet("POST",new String[]{"servers",getServerid(),"sessions",getId(),"transactions"}, params);
		JSONParser parser = new JSONParser();
		try {
			JSONObject obj = (JSONObject) parser.parse(result);
			Boolean ret = (Boolean) obj.get("result");
			if(ret == true){
				return (String) obj.get("tid");
			}
			
			return null;
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Check the status of the transaction
	 * 
	 * @param string $tid	Base64 encoded transaction identifier
	 * @return 		0 for new transaction, 1 for approved transaction, 2 for declined transactions or null if the transaction does not exist
	 */
	public Integer checkTransaction(String tid) {
		String result  = serverGet("GET",new String[]{"servers",getServerid(),"sessions",getId(),"transactions",tid}, null);
		JSONParser parser = new JSONParser();
		try {
			JSONObject obj = (JSONObject) parser.parse(result);
			Boolean ret = (Boolean) obj.get("result");
			if(ret == true){
				return (Integer) obj.get("tstatus");
			}
			
			return null;
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Return the javascript code needed to setup the websocket
	 * 
	 */
	public String wsinit(){
		//return "nauthwsinit('".htmlspecialchars($this->serverid)."','".base64_encode($this->getid())."',".
		//(($this->login())?"1":"0").",'".htmlspecialchars($this->wsuri)."','".htmlspecialchars($this->fallbackwsuri)."');";
		throw new IllegalStateException();
	}
}
