package com.henta.casperj;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.spongycastle.util.encoders.Hex;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * hehaoxian  ed25519 获取公私钥 20181509
 */
public class KeyPair {
    public static final Charset UTF_8 = Charset.forName("UTF-8");
    private static final EdDSANamedCurveSpec ED25519 = EdDSANamedCurveTable.ED_25519_CURVE_SPEC;

    private final String SIGNED_MESSAGE_PREFIX = "Lisk Signed Message:\n";

    private final EdDSAPublicKey mPublicKey;
    private final EdDSAPrivateKey mPrivateKey;

    /**
     * 公钥创建 KeyPair
     *
     * @param publicKey
     */
    public KeyPair(EdDSAPublicKey publicKey) {
        this(publicKey, null);
    }

    /**
     * 创建 KeyPair 构造器
     *
     * @param publicKey
     * @param privateKey
     */
    public KeyPair(EdDSAPublicKey publicKey, EdDSAPrivateKey privateKey) {
        mPublicKey = checkNotNull(publicKey, "publicKey cannot be null");
        mPrivateKey = privateKey;
    }

    /**
     * 是否可以签名
     */
    public boolean canSign() {
        return mPrivateKey != null;
    }

    /**
     * 种子生成KeyPair
     *
     * @param seed
     * @return {@link KeyPair}
     */
    public static KeyPair fromSecretSeed(byte[] seed) {
        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(seed, ED25519);
        EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(privKeySpec.getA().toByteArray(), ED25519);
        return new KeyPair(new EdDSAPublicKey(publicKeySpec), new EdDSAPrivateKey(privKeySpec));
    }


    /**
     * 通过公钥推导 KeyPair
     *
     * @param publicKey
     * @return {@link KeyPair}
     */
    public static KeyPair fromPublicKey(byte[] publicKey) {
        EdDSAPublicKeySpec publicKeySpec = new EdDSAPublicKeySpec(publicKey, ED25519);
        return new KeyPair(new EdDSAPublicKey(publicKeySpec));
    }

    /**
     * 随机创建 KeyPair
     *
     * @return a random  keypair.
     */
    public static KeyPair random() {
        java.security.KeyPair keypair = new KeyPairGenerator().generateKeyPair();
        return new KeyPair((EdDSAPublicKey) keypair.getPublic(), (EdDSAPrivateKey) keypair.getPrivate());
    }

    public byte[] getPublicKey() {
        return mPublicKey.getAbyte();
    }

    public byte[] getPrivateKey() {
        return mPrivateKey.getSeed();
    }

    /**
     * 获取公钥hex
     *
     * @return
     */
    public String getPublicKeyHex() {
        return Hex.toHexString(getPublicKey());
    }

    /**
     * 获取私钥hex,为真实私钥+公钥
     *
     * @return
     */
    public String getPrivateKeyHex() {
        return Hex.toHexString(getPrivateKey()) + getPublicKeyHex();
    }

    /**
     * 签名
     *
     * @param data
     * @return
     */
    public byte[] sign(byte[] data) {
        if (mPrivateKey == null) {
            throw new RuntimeException(
                    "KeyPair does not contain secret key. Use KeyPair.fromSecretSeed method to create a new KeyPair with "
                            + "a secret key.");
        }
        try {
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initSign(mPrivateKey);
            sgr.update(data);
            return sgr.sign();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 校验签名
     *
     * @param data
     * @param signature
     * @return
     * @throws RuntimeException
     */
    public boolean verify(byte[] data, byte[] signature) {
        try {
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initVerify(mPublicKey);
            sgr.update(data);
            return sgr.verify(signature);
        } catch (SignatureException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }
}
