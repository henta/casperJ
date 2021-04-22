package com.henta.casperj;

import org.spongycastle.util.encoders.Hex;

import java.math.BigDecimal;
import java.math.BigInteger;

/**
 * @author hehaoxian
 * @date 2019-02-25
 */
public class HexUtil {

//    public byte[] stringHexToBytesWithPrefix(String hex, String prefix) {
//        if (hex.startsWith(prefix)) {
//            hex = hex.substring(prefix.length());
//        }
//        if (x.length() % 2 != 0) {
//            x = "0" + x;
//        }
//        return Hex.decode(x);
//    }
//
//    public byte[] stringHexToBytesWithPrefix(String hex, byte[] prefix) {
//
//    }

    /**
     * double 转 16进制
     *
     * @param value
     * @param decimal
     * @return
     */
    public static String doubleToHex(Object value, int decimal) {
        // 转成 hex
        BigInteger temp = doubleToBigInteger(value, decimal);
        return "0x" + temp.toString(16);
    }

    /**
     * double 转 bigInteger
     *
     * @param value
     * @param decimal
     * @return
     */
    public static BigInteger doubleToBigInteger(Object value, int decimal) {

        BigDecimal bd1 = null;
        if (value instanceof Double) {
            bd1 = new BigDecimal(Double.toString((double) value));
        } else if (value instanceof BigDecimal) {
            bd1 = (BigDecimal) value;
        }

        // 转成 hex
        BigDecimal bd2 = new BigDecimal(Double.toString(Math.pow(10, decimal)));
        return bd1.multiply(bd2).toBigInteger();
    }

    /**
     * double 转 16进制
     *
     * @param x
     * @return
     */
    public static String intToHex(int x) {
        return Integer.toHexString(x);
    }

    /**
     * hex 转 byteArray
     *
     * @param x
     * @return
     * @throws Exception
     */
    public static byte[] StringHexToByteArray(String x) throws Exception {
        if (x.startsWith("0x")) {
            x = x.substring(2);
        }
        if (x.length() % 2 != 0) {
            x = "0" + x;
        }
        return Hex.decode(x);
    }
}
