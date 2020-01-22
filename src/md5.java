import java.math.*;
import java.lang.Number.*;
import java.lang.*;
import java.util.*;
class md5 {
	
	public String plaintext;
	public String ciphertext;
	
	public String MDBufferA = "00000001001000110100010101100111";
	public String MDBufferB = "10001001101010111100110111101111";
	public String MDBufferC = "11111110110111001011101010011000";
	public String MDBufferD = "01110110010101000011001000010000";
	
	public int[] AA;
	public int[] BB;
	public int[] CC;
	public int[] DD;

	public ArrayList<Integer> messageDigest;
	
	public int[][] InitialiseFunctionT() {
		MD5FunctionT functionT = new MD5FunctionT();
		int[][] functionTMatrix = new int[functionT.SeedData().size()][32];
		for(int i = 0; i < functionT.SeedData().size(); i++) {
			functionTMatrix[i] = BinaryArray(functionT.SeedData().get(i));
		}
		return functionTMatrix;
	}

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

	public int[] BinaryArray32bit(String inputstring) {
		int[] binaryArray = new int[32];
	    String[] inputstringelement = inputstring.split("");
	    for (int i = binaryArray.length; i > (binaryArray.length - inputstringelement.length); i--) {
	        binaryArray[i - 1] = Integer.parseInt(inputstringelement[(i - 1) - binaryArray.length + inputstringelement.length]);
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
	
	// method to perform bit array addition
	public int[] AddArray(int[] x, int[] y) {
		int[] result = new int[x.length];
		int resultInt = 0;
		for(int i = 0; i < x.length; i++) {
			resultInt += x[i]*Math.pow(2, i) + y[i]*Math.pow(2, i);
		}
		result = BinaryArray32bit(Integer.toBinaryString(resultInt));
		return result;
	}
	
	// method to perform bit array addition
	public int[] AddArray(int[] x, int[] y, int[] z, int[] xx) {
		int[] result = new int[x.length];
		int resultInt = 0;
		for(int i = 0; i < x.length; i++) {
			resultInt += x[i]*Math.pow(2, i) + y[i]*Math.pow(2, i) + z[i]*Math.pow(2, i) + xx[i]*Math.pow(2, i);
		}
		result = BinaryArray32bit(Integer.toBinaryString(resultInt));
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

	public int[] BitShiftLeft(int[] inputarray, int shiftvalue) {
		int[] outputArray = new int[inputarray.length];
		for(int i = 0; i < inputarray.length - shiftvalue; i++) {
			outputArray[i] = inputarray[i + shiftvalue];
		}
		for(int i = 0; i < shiftvalue; i++) {
			outputArray[inputarray.length - shiftvalue] = 0;
		}
		return outputArray;
	}
	
	private static int[] PartArray(int[] array, int size, int start) {
	    int[] part = new int[size];
	    System.arraycopy(array, start, part, 0, size);
	    return part;
	}
	
	public void md5Step3Process16bitWordBlocks(ArrayList<Integer> inputarraylist) {
		
		int[] inputarray = BinaryListToBinaryArray(inputarraylist);
		int[][] functionT = InitialiseFunctionT();
		int[][] arrayX = new int[16][32];
		
		ArrayList<Integer> output = new ArrayList<Integer>();
		
		/* Process each 16-word block. */
		
		for(int i = 0; i < (inputarray.length/512 - 1); i++) {
			/* Copy block i into X. */
		     for(int j = 0; j < 16; j++) {
		    	 arrayX[j] = PartArray(inputarray,32,32*i);
		     } /* end of loop on j */
		     
		     /* Save A as AA, B as BB, C as CC, and D as DD. */
		     this.AA = BinaryArray(this.MDBufferA);
		     this.BB = BinaryArray(this.MDBufferB);
		     this.CC = BinaryArray(this.MDBufferC);
		     this.DD = BinaryArray(this.MDBufferD);
		     
		     /* Round 1. */
		     /* Let [abcd k s i] denote the operation
		          a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
		     /* Do the following 16 operations. */
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[0],functionT[0])),7));	     
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[1],functionT[1])),12));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[2],functionT[2])),17));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[3],functionT[3])),22));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[4],functionT[4])),7));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[5],functionT[5])),12));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[6],functionT[6])),17));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[7],functionT[7])),22));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[8],functionT[8])),7));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[9],functionT[9])),12));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[10],functionT[10])),17));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[11],functionT[11])),22));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[12],functionT[12])),7));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[13],functionT[13])),12));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[14],functionT[14])),17));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[15],functionT[15])),22));
		     
		     /* Round 2. */
		     /* Let [abcd k s i] denote the operation
		          a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
		     /* Do the following 16 operations. */
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[1],functionT[16])),5));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[6],functionT[17])),9));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[11],functionT[18])),14));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[0],functionT[19])),20));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[5],functionT[20])),5));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[10],functionT[21])),9));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[15],functionT[22])),14));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[4],functionT[23])),20));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[9],functionT[24])),5));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[14],functionT[25])),9));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[3],functionT[26])),14));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[8],functionT[27])),20));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[13],functionT[28])),5));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[2],functionT[29])),9));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[7],functionT[30])),14));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[12],functionT[31])),20));
		     
		     /* Round 3. */
		     /* Let [abcd k s i] denote the operation
		          a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
		     /* Do the following 16 operations. */
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[5],functionT[32])),4));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[8],functionT[33])),11));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[11],functionT[34])),16));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[14],functionT[35])),23));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[1],functionT[36])),4));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[4],functionT[37])),11));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[7],functionT[38])),16));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[10],functionT[39])),23));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[13],functionT[40])),4));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[0],functionT[41])),11));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[3],functionT[42])),16));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[6],functionT[43])),23));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[9],functionT[44])),4));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[12],functionT[45])),11));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[15],functionT[46])),16));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[2],functionT[47])),23));
		     
		     /* Round 4. */
		     /* Let [abcd k s i] denote the operation
		          a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
		     /* Do the following 16 operations. */
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[0],functionT[48])),6));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[7],functionT[49])),10));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[14],functionT[50])),15));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[5],functionT[51])),21));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[12],functionT[52])),6));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[3],functionT[53])),10));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[10],functionT[54])),15));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[1],functionT[55])),21));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[8],functionT[56])),6));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[15],functionT[57])),10));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[6],functionT[58])),15));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[13],functionT[59])),21));
		     
		     this.AA = AddArray(this.BB,BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),arrayX[4],functionT[60])),6));
		     this.DD = AddArray(this.AA,BitShiftLeft((AddArray(this.DD,md5FunctionF(this.AA,this.BB,this.CC),arrayX[11],functionT[61])),10));
		     this.CC = AddArray(this.DD,BitShiftLeft((AddArray(this.CC,md5FunctionF(this.DD,this.AA,this.BB),arrayX[2],functionT[62])),15));
		     this.BB = AddArray(this.CC,BitShiftLeft((AddArray(this.BB,md5FunctionF(this.CC,this.DD,this.AA),arrayX[9],functionT[63])),21));
		     
		     
		     /* Then perform the following additions. (That is increment each
		        of the four registers by the value it had before this block
		        was started.) */
		     
		     this.AA = AddArray(this.AA, BinaryArray(this.MDBufferA));
		     this.BB = AddArray(this.BB, BinaryArray(this.MDBufferB));
		     this.CC = AddArray(this.CC, BinaryArray(this.MDBufferC));
		     this.DD = AddArray(this.DD, BinaryArray(this.MDBufferD));
		     
		     /* end of loop on i */ 
		}
		
		for(int i = 0; i < 32; i ++) {
			output.add(this.AA[31 - i]);
		}
		for(int i = 0; i < 32; i ++) {
			output.add(this.BB[31 - i]);
		}
		for(int i = 0; i < 32; i ++) {
			output.add(this.CC[31 - i]);
		}
		for(int i = 0; i < 32; i ++) {
			output.add(this.DD[31 - i]);
		}
		
		// Message to Zac ..... likely to do with rotate left? and addition?
		
		for(int i = 0; i < output.size(); i++) {
			System.out.print(output.get(i));
		}
		
		this.messageDigest = output;
	}

	public String MessageDigestString() {
		String messageOutput = "";
		for(int i = 0; i < 16; i++) {
			int tempVal = 0;
			for(int j = 0; j < 8; j++) {
				tempVal += this.messageDigest.get(i*8 + j)*Math.pow(2, j);
			}
			messageOutput.concat(String.valueOf((char)tempVal));
		}
		return messageOutput;	
	}
}