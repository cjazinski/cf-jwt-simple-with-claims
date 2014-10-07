/**
* 
* This is a complete rip off from jwt-simple port on git
* I wanted to modify it to suite my needs and update it
* to use CFScript
* 
* @output true
* @accessors true
*/
component {
	property key;
	property algorithmMap;

	//It actually returns its own object
	public any function init(required any key) {
		setKey(arguments.key);
		setAlgorithmMap({
			"HS256":"HmacSHA256",
			"HS384":"HmacSHA384",
			"HS512":"HmacSHA512"
		});
		return this;
	}

	public any function decode(required any token) {
		if (listLen(arguments.token, '.') != 4)
			throw (type='Invalid Token', message='Token should contain 3 segments');

		var header = deserializeJSON(base64UrlDecode(getToken(arguments.token, 1, '.')));
		var claims = deserializeJSON(base64UrlDecode(getToken(arguments.token,2,".")));
		var payload = deserializeJSON(base64UrlDecode(getToken(arguments.token,3,".")));
		var signiture = getToken(arguments.token,4,".");

		if (listFindNoCase(structKeyList(getAlgorithmMap()),header.alg) == 0)
			throw(type='Invalid Token', message:'Algorithm not supported');

		//Verify Signiture
		var signInput = listGetAt(arguments.token,1,".") & "." & listGetAt(arguments.token,2,".") & '.' & listGetAt(arguments.token,3,".") & '.';
		if (signiture != sign(signInput,getAlgorithmMap()[header.alg]))
			throw(type:'Invalid Token', message:'Signiture verification failed');

		writeDump(claims);
		if (DateCompare(now(), convertEpochTime(claims.exp)) == 1)
			throw(type:'Expired', message:'The token has expired');

		return payload;
	}

	public any function encode(required any payload, algorithm = 'HS256') {
		var hashAlg = 'HS256';
		var segments = '';
		var claims = setTokenClaims();

		if (listFindNoCase(structKeyList(getAlgorithmMap()), arguments.algorithm))
			hashAlg = arguments.algorithm;

		//Add Header
		segments &= base64UrlEscape(
			toBase64(serializeJSON({'typ':'JWT', 'alg':hashAlg}))
			) & '.';
		//Add Claims
		segments &= base64UrlEscape(toBase64(serializeJSON(claims))) & '.';
		//Add payload
		segments &= base64UrlEscape(toBase64(serializeJSON(arguments.payload))) & '.';
		//Sign
		segments &= sign(segments,getAlgorithmMap()[hashAlg]) & ".";
		return segments;
	}

	public any function debug() {
		var a = sign('this is the hook');
		writeDump(a);
	}

	public boolean function verify(required any token) {
		var isValid = true;

		try {
			decode(token);
		} catch (any e) {
			isValid = false;
		}
	
		return isValid;
	}

	private any function sign(required string msg, algorithm = 'HmacSHA256') {
		var key = createObject('java', 'javax.crypto.spec.SecretKeySpec');
		key.init(getKey().getBytes(), arguments.algorithm);
		var mac = createObject('java', 'javax.crypto.Mac').getInstance(arguments.algorithm);
		mac.init(key);
		return base64UrlEscape(toBase64(mac.doFinal(msg.getBytes())));
	}

	private any function base64UrlEscape(required any str) {
		return reReplace(reReplace(reReplace(arguments.str, "\+", "-", "all"), "\/", "_", "all"),"=", "", "all");
	}

	private any function base64UrlUnescape(required any str) {
		var base64str = reReplace(reReplace(arguments.str, "\-", "+", "all"), "\_", "/", "all");
		var padding = repeatstring("=",4 - len(base64str) mod 4);
		return base64str & padding;
	}

	private any function base64UrlDecode(required any str) {
		return toString(toBinary(base64UrlUnescape(arguments.str)));
	}

	private any function setTokenClaims() {
		var c = {
			'iss':'Chris_Jazinski',
			'exp': tokenExpires(epochTime()),
			'iat': epochTime()
		};
		return c;
	}

	private any function tokenExpires(required any epoch) {
		var hours = 0.25; 
		return int(epoch + (3600 * hours));
	}

	private any function convertEpochTime(any seconds) {
		// set the base time from when epoch time starts
		var startDate = createdatetime( '1970','01','01','00','00','00' );
			
		if (!isnumeric( arguments.seconds ) )
			return '';
			
		// return the date
		// this adds the seconds to the startDate and the converts it to to a local time from UTC format
		//return dateConvert( "utc2Local", dateadd( 's', arguments.seconds, startDate ) );
		return dateadd( 's', arguments.seconds, startDate );
	}

	private any function epochTime() {

		// set the base time from when epoch time starts
		var startDate = createdatetime( '1970','01','01','00','00','00' );
			
		var datetimeNow = dateConvert( "local2Utc", now() );
			
		//return datediff( 's', startdate, datetimeNow );
		return datediff('s', startdate, now());
	}
}