import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class Assignment2_12519227 {
	private static final int MAX_TRIES = 10;
	enum LowerLimit { ZERO, ONE };
	public static final String prime_mod = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd"
			+ "ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc"
			+ "8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f"
			+ "47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
	public static final String generator1 = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2"
			+ "e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864"
			+ "1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496"
			+ "64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
	
	public static void main(String[] args) throws Exception {
		
		BigInteger p = new BigInteger(prime_mod, 16);
		int randomX = generateRandom(p, LowerLimit.ONE);
		BigInteger g = new BigInteger(generator1, 16);
		
		BigInteger y = g.modPow(BigInteger.valueOf(randomX), p);
		System.out.print("y as hex value = ");
		printAsHex(y);
		
		byte[] message = readInputFile();
		BigInteger r = null;
		BigInteger s = null;
		boolean sIsValid = false;
		
		while(!sIsValid){
			int randomK;
			BigInteger k;
			BigInteger gcd;
			while (true) {
				randomK = generateRandom(p, LowerLimit.ZERO);
				k = BigInteger.valueOf(randomK);
				gcd = checkGCD(k, p.subtract(BigInteger.ONE));
				if (gcd.equals(BigInteger.valueOf(1)))
					break;
			}
			
			r = g.modPow(BigInteger.valueOf(randomK), p);
			System.out.print("r as hex value = ");
			printAsHex(r);
			
			s = computeS(message, randomX, r, k, p.subtract(BigInteger.ONE));
			if(s.compareTo(BigInteger.ZERO) != 0){
				sIsValid = true;
			}
		}
		System.out.print("s as hex value = ");
		printAsHex(s);
		
	}
	
	private static byte[] readInputFile() throws IOException {
		// Get file path and read in file
		Path filePath = Paths.get("Assignment2_12519227.java.zip");
		byte[] inputFileBuffer = Files.readAllBytes(filePath);
		return inputFileBuffer;
	}

	private static void printAsHex(BigInteger BigInt) {
		// Print as Hex String
		String s = BigInt.toString(16);
		System.out.println(s);
	}

	private static BigInteger computeS(byte[] message, int x, BigInteger r, BigInteger k, BigInteger pMinus1)
			throws Exception {
		
		// SHA Hash of message m, H(m)
		byte[] m = applyHashing(message);
		BigInteger HashOfM = new BigInteger(m);
		
		
		// xr = x * r
		BigInteger xr = BigInteger.valueOf(x).multiply(r);
		
		// hm_xr = H(m) - xr
		BigInteger hm_xr = HashOfM.subtract(xr);
		
		//returns a BigInteger array with the modular inverse at ans[1]
		BigInteger ans[] = getModInverse(k, pMinus1);
		BigInteger modInverse = ans[1];
		
		// if the modular inverse is a negative, add it to the modulus
		if (modInverse.compareTo(BigInteger.ZERO) == -1) {
			modInverse = modInverse.add(pMinus1);
		}

		BigInteger s = modInverse.multiply(hm_xr);
		s = s.mod(pMinus1);
		return s;
	}

	// Extended Euclidean Algorithm, returns an array with the modular inverse
	// at the 2nd index
	private static BigInteger[] getModInverse(BigInteger a, BigInteger b) {
		BigInteger[] ans = new BigInteger[3];
		BigInteger q;
		if (b.equals(BigInteger.valueOf(0))) {
			ans[0] = a;
			ans[1] = BigInteger.valueOf(1);
			ans[2] = BigInteger.valueOf(0);
		} else {
			q = a.divide(b);
			ans = getModInverse(b, a.mod(b));
			BigInteger temp = ans[1].subtract(ans[2].multiply(q));
			ans[1] = ans[2];
			ans[2] = temp;
		}

		return ans;
	}

	static BigInteger checkGCD(BigInteger a, BigInteger b) {
		if (a.compareTo(BigInteger.valueOf(0)) == 0 || b.compareTo(BigInteger.valueOf(0)) == 0)
			return a.add(b); // base case
		return checkGCD(b, a.mod(b));
	}


	private static int generateRandom(BigInteger p, LowerLimit ll) {
		int random;
		switch (ll){
			case ZERO:
				random = generateRandomInt(p, 0);
				break;
			default:
				random = generateRandomInt(p, 1);
				break;
		}
		return random;
	}
	
	private static int generateRandomInt(BigInteger p, int ll) {
		int count = 0;
		int random = 0;
		Random rand;
		BigInteger x;
		
		// loop while random is not greater than the lower limit
		while(!(random > ll)) {
			rand = new SecureRandom();
			random = Math.abs(rand.nextInt());
			x = BigInteger.valueOf(random);
			while ((x.compareTo(p.subtract(BigInteger.valueOf(1))) != -1)) {
				random = Math.abs(rand.nextInt());
				x = BigInteger.valueOf(random);
				count++;
				if (count < MAX_TRIES) {
					throw new RuntimeException("Failed to create random number less than p-1");
				}
			}
		}
		return random;
	}

	private static byte[] applyHashing(byte[] input) throws NoSuchAlgorithmException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		input = sha256.digest(input);
		return input;
	}
}
