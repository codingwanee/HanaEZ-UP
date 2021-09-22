package com.ez.hana.util;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
 
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.apache.commons.codec.binary.Base32;
 
public class OtpResultServlet extends HttpServlet {
 
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
    protected void service(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
         
        String userCodeStr = req.getParameter("userCode");
        long userCode = Integer.parseInt(userCodeStr);
        String encodedKey = req.getParameter("encodedKey");
        long time = new Date().getTime();
        long timeCode =  time / 30000;
         
        boolean codeChecking = false;
        try {
            // 키, 코드, 시간으로 일회용 비밀번호가 맞는지 일치 여부 확인.
            codeChecking = checkCode(encodedKey, userCode, timeCode);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
         
        // 일치한다면 true 반환
        System.out.println("is checkCode true : " + codeChecking);
         
    }
 
    private static boolean checkCode(String secret, long code, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
 
        int window = 3;
        for (int i = -window; i <= window; ++i) {
            long hash = verifyCode(decodedKey, t + i);
 
            if (hash == code) {
                return true;
            }
        }
 
        // hash와 code가 일치하지 않을 시 false 반환
        return false;
    }
     
    private static int verifyCode(byte[] key, long t)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
 
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);
 
        int offset = hash[20 - 1] & 0xF;
 
        long truncatedHash = 0; 
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
 
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
 
        return (int) truncatedHash;
    }
     
}