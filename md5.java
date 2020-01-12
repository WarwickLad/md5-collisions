import java.math.*;
import java.lang.Number.*;
import java.lang.*;
import java.util.*;

class md5 {
	
	public String plaintext;
	public String ciphertext;
	
	public String MDBufferA = "01100111010001010010001100000001";
	public String MDBufferB = "11101111110011011010101110001001";
	public String MDBufferC = "10011000101110101101110011111110";
	public String MDBufferD = "00010000001100100101010001110110";
	
	public int[] AA;
	public int[] BB;
	public int[] CC;
	public int[] DD;

	public int[] X;
	public int[] Y;
	public int[] Z;
	
	public long[] T = md5FunctionT();
	
	public void SetPlaintext(String inputstring) {
		this.plaintext = inputstring;
	}
	
	public String GetPlaintext() {
		return this.plaintext;
	}
	
	public void SetCiphertext(String inputstring) {
		this.ciphertext = inputstring;
	}
	
	public String GetCiphertext() {
		return this.ciphertext;
	}
	
	// method to convert an input string into a binary representation using BigInteger format
	public BigInteger TextToBinary(String inputstring) {
		BigInteger binaryInt = new BigInteger(inputstring.getBytes());
		return binaryInt;
	}
	
	// method to covert a binary value in BigInteger form into a string representation (e.g, 1010101 -> '1010101')
	public String TextToBinaryString(BigInteger inputinteger) {
		String binaryString = inputinteger.toString(2);
		return binaryString;
	}

	// method to convert a binary value in string representation to an int array format (e.g, '1010101' -> [1,0,1,0,1,0,1]
	public int[] BinaryArray(String inputstring) {
	    int[] binaryArray = new int[inputstring.length()];
	    String[] inputstringelement = inputstring.split("");
	    for (int i = 0; i < binaryArray.length; i++) {
	        binaryArray[i] = Integer.parseInt(inputstringelement[i]);
	    }
	    return binaryArray;
	}

	public int[] BinaryListToBinaryArray(ArrayList<Integer> inputarray) {
		int[] outputArray = new int[inputarray.size()];
		for(int i = 0; i < inputarray.size(); i++) {
			outputArray[i] = inputarray.get(i);
		}
		return outputArray;
	}
	
	public int logicalOR(int a, int b) {
		if(a == 0 && b == 0) {
			return 0;
		} else {
			return a;
		}
	}

	public int logicalNOT(int a) {
		if(a == 0) {
			return a;
		} else {
			return 0;
		}
	}

	public int logicalXOR(int a, int b) {
		if(a == b) {
			return 0;
		} else {
			if(a == 0) {
				return b;
			} else {
				return a;
			}
		}
	}
	
	public int[] arrayAddition(int[] a, int[] b) {
		int[] result = new int[a.length];
		for(int i = 0; i < a.length; i++) {
			result[i] = a[i] + b[i];
		}
		return result;
	}
	
	public ArrayList<Integer> BinaryArrayToBinaryList(int[] inputarray) {
		ArrayList<Integer> outputArrayList = new ArrayList<Integer>();
		for(int i = 0; i < inputarray.length; i++) {
			outputArrayList.add(inputarray[i]);
		}
		return outputArrayList;
	}
	
	// method to conduct step 1 of MD5 hash: appending padded bits to that message length is congruent to 448, modulo 512. First
	// bit of padding is 1, all subsequent padded bits are 0
	public ArrayList<Integer> md5Step1AppendBits(int[] inputarray) {
		int arrayLength = inputarray.length;
		int padValue = 0;
		ArrayList<Integer> paddedArray = new ArrayList<Integer>();
		if(arrayLength%512 < 448) {
			padValue = Math.abs(448 - arrayLength%512);
		} else {
			padValue = 448 + Math.abs(448 - arrayLength%512);
		}
		for(int i = 0; i < arrayLength; i ++) {
			paddedArray.add(inputarray[i]);
		}
		for(int i = 0; i < padValue; i++) {
			if(i < 1) {
				paddedArray.add(1);
			} else {
				paddedArray.add(0);
			}
		}
		return paddedArray;
	}

	// need to convert bit size into 64 bit representation
	public ArrayList<Integer> md5Step2AppendLength(ArrayList<Integer> inputarraylist) {
		ArrayList<Integer> paddedArrayLengthAppended = (ArrayList<Integer>) inputarraylist.clone();
		int arrayLength = inputarraylist.size();
		String[] arrayLengthBinary = Integer.toBinaryString(arrayLength).split("");
		ArrayList<Integer> arrayLengthBinary64bit = new ArrayList<Integer>();
		for(int i = 0; i < 64; i++) {
			if(i < (64-arrayLengthBinary.length)) {
				arrayLengthBinary64bit.add(0);
			} else {
				arrayLengthBinary64bit.add(Integer.parseInt(arrayLengthBinary[i - 64 + arrayLengthBinary.length]));
			}
		}
		for(int i = 0; i < arrayLengthBinary64bit.size(); i++) {
			paddedArrayLengthAppended.add(arrayLengthBinary64bit.get(i));
		}
		return paddedArrayLengthAppended;
	}
	
	// unit tests for each of these
	public int[] md5FunctionF(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalOR((X[i]*Y[i]),(logicalNOT(X[i])))*Z[i];
		}
		return result;
	}
	
	public int md5FunctionF(int X, int Y, int Z) {
		int result = logicalOR((X*Y),(logicalNOT(X)))*Z;
		return result;
	}
	
	public int[] md5FunctionG(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalOR((X[i]*Z[i]),Y[i])*logicalNOT(Z[i]);
		}
		return result;
	}

	public int[] md5FunctionH(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalXOR(logicalXOR(X[i],Y[i]),Z[i]);
		}
		return result;
	}
	
	public int[] md5FunctionI(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalXOR(Y[i],logicalOR(X[i],logicalNOT(Z[i])));
		}
		return result;
	}

	public long[] md5FunctionT() {
		long k = 4294967296L;
		long[] T = new long[64];
		for(double i = 0; i < 64; i++) {
			T[(int) i] = (long) (k*Math.abs(Math.sin(i)));
		}
		return T;
	}

	public ArrayList<Integer> md5Step3Process16bitWordBlocks(ArrayList<Integer> inputarraylist) {
		/* Process each 16-word block. */
		this.X = new int[16];
		this.Y = new int[16];
		this.Z = new int[16];
		int[] tempA = BinaryArray(this.MDBufferA);
		int[] tempB = BinaryArray(this.MDBufferB);
		int[] tempC = BinaryArray(this.MDBufferC);
		int[] tempD = BinaryArray(this.MDBufferD);
		
		for(int i = 0; i < (inputarraylist.size()/16 - 1); i++) {
			/* Copy block i into X. */
		     for(int j = 0; j < 16; j++) {
		    	 X[j] = inputarraylist.get((i*16) + j);
		     } /* end of loop on j */
		     
		     /* Save A as AA, B as BB, C as CC, and D as DD. */
		     this.AA = BinaryArray(this.MDBufferA);
		     this.BB = BinaryArray(this.MDBufferA);
		     this.CC = BinaryArray(this.MDBufferA);
		     this.DD = BinaryArray(this.MDBufferA);
		     
		     /* Round 1. */
		     /* Let [abcd k s i] denote the operation
		          a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
		     /* Do the following 16 operations. */
		     
		     for(int k = 0; k < 16; k++) {
		    	 for(int ii = 0; ii < this.AA.length; ii++) {
		    		 tempA[ii] = this.BB[ii] + ((this.AA[ii] + md5FunctionF(this.BB[ii],this.CC[ii],this.DD[ii])) + X[k] + ((int) this.T[k + 1]));
		    	 }
		     }
		     
		     [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
		     [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
		     [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
		     [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
		}
	}

}