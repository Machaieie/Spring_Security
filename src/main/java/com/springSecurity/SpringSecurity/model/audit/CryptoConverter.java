package com.springSecurity.SpringSecurity.model.audit;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Component
@Converter
public class CryptoConverter implements AttributeConverter<String, String> {

    private static final String ALG = "AES";
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    private final SecretKeySpec keySpec;
    private final SecureRandom random = new SecureRandom();

    public CryptoConverter(@Value("${app.crypto.key}") String base64Key) {
        try {
            byte[] key = Base64.getDecoder().decode(base64Key);
            this.keySpec = new SecretKeySpec(key, ALG);
        } catch (Exception e) {
            throw new IllegalStateException("Chave de criptografia inválida", e);
        }
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null) return null;
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] cipherText = cipher.doFinal(attribute.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("Erro ao criptografar", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null) return null;
        try {
            byte[] all = Base64.getDecoder().decode(dbData);
            byte[] iv = java.util.Arrays.copyOfRange(all, 0, IV_BYTES);
            byte[] cipherText = java.util.Arrays.copyOfRange(all, IV_BYTES, all.length);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] plain = cipher.doFinal(cipherText);
            return new String(plain, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Erro ao descriptografar", e);
        }
    }
}
