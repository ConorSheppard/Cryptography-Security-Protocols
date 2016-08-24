import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CryptoAssign1_12519227 {
    
    private static final int BLOCK_SIZE = 16;
    
    private static final int HASH_ITERATIONS = 200;

    public static void main(String[] args) throws Exception {
        
        byte[] password = createPassword();

        byte[] iv = create_IV_Value();

        byte[] passAndSalt = createEncryptionKey(password);

        byte[] inputFileBuffer = readInputFile();

        // Add padding to file
        byte[] paddedFileBuffer = addPadding(inputFileBuffer);

        // Encrypt binary file with AES
        byte[] encryptedFileBuffer = aesEncryptFile(iv, passAndSalt, paddedFileBuffer);
        printEncryptedFileAsHex(encryptedFileBuffer);

        // Encypt password using RSA
        BigInteger encryptedPassword = rsaEncryptPassword(password);
        printEncryptedPasswordAsHex(encryptedPassword);
    }

    private static byte[] createPassword() throws UnsupportedEncodingException {
        String pw = "uN0bv10uSpAsSVV0rD";
        byte[] password = pw.getBytes("UTF8");
        return password;
    }

    private static byte[] create_IV_Value() {
        // generate random 128-bit (16-byte) IV
        byte[] iv = randomByteGen();
        System.out.print("IV as hex value = ");
        // Print iv as a Hex String
        printAsHex(iv);
        System.out.println();
        return iv;
    }

    private static void printEncryptedFileAsHex(byte[] encryptedFileBuffer) {
        System.out.print("Encrypted file as hex value = ");
        // Print the encrypted file as a Hex String
        printAsHex(encryptedFileBuffer);
        System.out.println();
    }

    private static void printEncryptedPasswordAsHex(BigInteger encryptedPassword) {
    	
        System.out.print("Encrypted password as hex value = ");
        // Print pEncrypt as a Hex String
        String s = encryptedPassword.toString(16);
        System.out.println(s);
    }

    private static byte[] readInputFile() throws IOException {
    	
        // Get file path and read in file
        Path filePath = Paths.get("src/CryptoAssign1_12519227.java.zip");
        byte[] inputFileBuffer = Files.readAllBytes(filePath);
        return inputFileBuffer;
    }

    private static byte[] createEncryptionKey(byte[] password)
            throws NoSuchAlgorithmException {
    	
        // generate random 128-bit (16-byte) salt
        byte[] salt = randomByteGen();
        System.out.print("Salt as hex value = ");
        // Print slat as a Hex String
        printAsHex(salt);
        System.out.println();

        // concatenate password and salt
        byte[] passAndSalt = byteConcat(password, salt);

        // Hash password+salt 200 times
        passAndSalt = applyHashing(passAndSalt);
        return passAndSalt;
    }

    private static void printAsHex(byte[] byteToHex) {
    	
        StringBuilder hexByte = new StringBuilder(byteToHex.length * 2);
        for (byte b : byteToHex)
            hexByte.append(String.format("%02x", b & 0xff));
        System.out.println(hexByte);
    }

    private static byte[] applyHashing(byte[] passAndSalt)
            throws NoSuchAlgorithmException {
    	
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < HASH_ITERATIONS; i++) {
            passAndSalt = sha256.digest(passAndSalt);
        }
        return passAndSalt;
    }

    private static byte[] randomByteGen() {
    	
        final Random r = new SecureRandom();
        byte[] randomByte = new byte[16];
        r.nextBytes(randomByte);
        return randomByte;
    }

    private static byte[] byteConcat(byte[] b1, byte[] b2) {
    	
        byte[] newByte = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, newByte, 0, b1.length);
        System.arraycopy(b2, 0, newByte, b1.length, b2.length);
        return newByte;
    }

    private static byte[] addPadding(byte[] inputFile) {

        byte[] paddedInputFileBuffer = null;
        int fileLength = inputFile.length;
        if (fileLength % BLOCK_SIZE == 0) {
            // new block
            paddedInputFileBuffer = new byte[inputFile.length + BLOCK_SIZE];
            System.arraycopy(inputFile, 0, paddedInputFileBuffer, 0, inputFile.length);
            paddedInputFileBuffer[inputFile.length] = -128;            
            
        } else {
            // pad out the last block
            int paddingLength = BLOCK_SIZE - (fileLength % BLOCK_SIZE);
            paddedInputFileBuffer = new byte[inputFile.length + paddingLength];
            System.arraycopy(inputFile, 0, paddedInputFileBuffer, 0, inputFile.length);
            paddedInputFileBuffer[inputFile.length] = -128;
     
        }
        return paddedInputFileBuffer;
    }

    private static byte[] aesEncryptFile(byte[] iv, byte[] encryptionKey,
            byte[] paddedFile) throws Exception {
        
        byte[] encryptedFileBuffer = null;
        Cipher aesCipher = createAesCipher(iv, encryptionKey);
        encryptedFileBuffer = aesCipher.doFinal(paddedFile);

        return encryptedFileBuffer;
    }

    private static Cipher createAesCipher(byte[] iv, byte[] encryptionKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException {
    	
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec key = new SecretKeySpec(encryptionKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher;
    }

    private static BigInteger rsaEncryptPassword(byte[] password) {
    	
        BigInteger m = new BigInteger(password);
        String hexStr = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190"
                + "ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d"
                + "3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c8652"
                + "01fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
        BigInteger N = new BigInteger(hexStr, 16);
        String eAsBinary = Integer.toBinaryString(65537);
        int eLen = eAsBinary.length();
        BigInteger c = new BigInteger("1");
        // Manual Modular Exponentiation
        for (int j = eLen - 1; j >= 0; j--) {
            c = c.multiply(c).mod(N);
            if (eAsBinary.charAt(j) == '1')
                c = c.multiply(m).mod(N);
        }
        return c;
    }
}