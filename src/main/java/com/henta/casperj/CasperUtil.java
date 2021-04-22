package com.henta.casperj;

import com.henta.casperj.helper.Hex;
import com.rfksystems.blake2b.security.Blake2b256Digest;

import java.nio.ByteBuffer;

/**
 * @author hhx
 */
public class CasperUtil {

    public static String createAccountHash(byte[] privateKey) {
        byte[] ed25519Name = {(byte) 101, (byte) 100, (byte) 50, (byte) 53, (byte) 53, (byte) 49, (byte) 57};
        byte[] ed25519Prefix = {(byte) 0};

        KeyPair keyPair = KeyPair.fromSecretSeed(privateKey);
        System.out.println(keyPair.getPublicKeyHex());
        ByteBuffer byteBuffer = ByteBuffer.allocate(40);
        byteBuffer.put(ed25519Name);
        byteBuffer.put(ed25519Prefix);
        byteBuffer.put(keyPair.getPublicKey());
        Blake2b256Digest blake2b256Digest = new Blake2b256Digest();
        String genericHash = Hex.encode(blake2b256Digest.digest(byteBuffer.array()));
        System.out.println(genericHash);
        return genericHash;
    }

    /**
     * ed25519
     *
     * @param privateKey
     * @return
     */
    public static String createAccountHex(byte[] privateKey) {
        KeyPair keyPair = KeyPair.fromSecretSeed(privateKey);
        return "01" + keyPair.getPrivateKeyHex();
    }

    public static void main(String[] args) {
        createAccountHash(Hex.decode("1e2b178993997a213b7f5836fa7f7be922ea62e675a5f05235f9ba231807ef69"));
    }
}
