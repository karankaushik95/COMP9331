/*
 * Written by Karan Kaushik for COMP9331 
 * Computer Networks - 18s2
 * 
 * */





import java.io.*; 
import java.net.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;   
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ThreadLocalRandom;



public class sender {

	//long start_time = System.currentTimeMillis();
	static long nb_of_bytes_sent = 0; 
	static long original_sequence_number = 0; 
	static long segment_number_pdf = 0;  
	static ArrayList<Long> sent_packets= new ArrayList<Long>();
	static boolean syn_done = false;
	static boolean time_for_fin = false;

	static ByteArrayOutputStream log = new ByteArrayOutputStream();
	static ArrayList<String> data = new ArrayList<String>();
	static long start_time = System.currentTimeMillis();
	
	private static Map<Long, byte[]> packetMaker(byte[] file, int maxSegmentSize){

		Map<Long, byte[]> packets = new TreeMap<Long, byte[]>();
		for(int i=0; i<file.length; i += maxSegmentSize) {
			long temporary_i = i;
			if(i + maxSegmentSize <= file.length-1) 
				packets.put(temporary_i, Arrays.copyOfRange(file, i, i+maxSegmentSize));				 
			else
				packets.put(temporary_i, Arrays.copyOfRange(file, i, file.length));
		}	


		return packets;
	}

	/*
	 * Takes in the input file and writes it to a byte array using a FileInputStream 
	 * 
	 * 
	 * */
	private static byte[] readFileToByteArray(File inputFile) throws FileNotFoundException, IOException{


		byte[] fileToByteArray = new byte[(int)inputFile.length()];
		FileInputStream fis = new FileInputStream(inputFile);
		fis.read(fileToByteArray); //read file into bytes[]
		fis.close();

		return fileToByteArray;
	}

	/*
	 * getChecksum() method is used to get a checkSum for the packet. 
	 * It sums up the bytes of the array and and returns it as a long
	 * */
	
	private static int connectionEstablishment(String ipAddress, int port, DatagramSocket pdfSocket) throws UnknownHostException, IOException{

		/*Header description
		 * 0) Sequence number
		 * 1) Acknowledgement number
		 * 2) Syn Flag
		 * 3) Ack flag
		 * 4) Fin flag
		 * 5) Data flag
		 * 6) Checksum
		 * 7) Size of payload
		 * 8) Size of header
		 * 9) Actual data	
		 */
		//Initial SYN
		String message = original_sequence_number+"\n0\nT\nF\nF\nF\n";  //Doesn't have acknowledgement number in the beginning. Don't want to mess up the whole header for one flag. 0000 arbitrary value
		
		data.add(new LogData("snd", System.currentTimeMillis() - start_time, "S", original_sequence_number, 0, 0).toString());
		
		InetAddress localhost = InetAddress.getByName(ipAddress);
		DatagramPacket sending = new DatagramPacket(message.getBytes(), message.length(), localhost, port);
		pdfSocket.send(sending);

		nb_of_bytes_sent += message.length();
		//SYN-ACK
		DatagramPacket request = new DatagramPacket(new byte[1024], 1024);
		pdfSocket.receive(request);
		
		String temp_string = new String(request.getData());
		String[] response = temp_string.split("\\n");
		original_sequence_number++;
		data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "SA", original_sequence_number, 0, Long.parseLong(response[1])).toString());
		if (response[2].contains("T") && response[3].contains("T")) {
		//	System.out.println("SYN-ACK received");
			String syn_ack = response[1]+"\n"+Integer.parseInt((response[0])+ 1) +"\nF\nT\nF\nF\n";
			sending = new DatagramPacket(syn_ack.getBytes(), syn_ack.length(), localhost, port);
			data.add(new LogData("snd", System.currentTimeMillis() - start_time, "A", original_sequence_number, 0, 1).toString());
			pdfSocket.send(sending);
			nb_of_bytes_sent += message.length();
			original_sequence_number = Long.parseLong(response[1]);
		}else {
			//Do nothing because it is not expected that response wouldn't be received. Just for the sake of completeness
		}
		// Connection has been successfully established.
		// Timeout also not given, because it is not expected to timeout
		syn_done = true;
		return Integer.parseInt(response[0] + 1);
	}

	private static void connectionTeardown(String ipAddress, int port, DatagramSocket pdfSocket, Map<Long, byte[]> packets) throws UnknownHostException, IOException{

		//Initial FIN
		long temp = 0;
		for(long key: packets.keySet()) {
			temp = key;
		}
		temp++;
		String message = temp+"\n0000\nF\nF\nT\nF\n"; 
		InetAddress localhost = InetAddress.getByName(ipAddress);
		DatagramPacket sending = new DatagramPacket(message.getBytes(), message.length(), localhost, port);
		
		data.add(new LogData("snd", System.currentTimeMillis() - start_time, "F", temp, 0, 1).toString());
		pdfSocket.send(sending);
		//Thread.sleep(1000);
		nb_of_bytes_sent += message.length();
		//ACK
		DatagramPacket request = new DatagramPacket(new byte[1024], 1024);
		pdfSocket.receive(request);
		String temp_string = new String(request.getData());
		String[] response = temp_string.split("\\n");
		// ACK
		data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "A", Long.parseLong(response[0]), 0, temp).toString());
		if (response[3].contains("T")) { 
			//System.out.println("ACK received");
			original_sequence_number = Long.parseLong(response[1]);
		}else {
			//Do nothing because it is not expected that response wouldn't be received. Just for the sake of completeness
		}

		DatagramPacket fin = new DatagramPacket(new byte[1024], 1024);
		pdfSocket.receive(fin);
		temp_string = new String(fin.getData());
		data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "F", Long.parseLong(response[0]), 0, temp+1).toString());
		response = temp_string.split("\\n");
		// ACK
		if (response[4].contains("T")) { 
			//system.out.println("FIN received");

			//Thread.sleep(1000);
		}else {
			//Do nothing because it is not expected that response wouldn't be received. Just for the sake of completeness
		}

		String fin_ack = response[1]+"\n"+(temp+1) +"\nF\nT\nF\nF\n";
		sending = new DatagramPacket(fin_ack.getBytes(), fin_ack.length(), localhost, port);
		data.add(new LogData("snd", System.currentTimeMillis() - start_time, "A",temp+1 , 0, Long.parseLong(response[0])).toString());
		pdfSocket.send(sending);
		nb_of_bytes_sent += fin_ack.length();
		// Connection has been successfully torn down.
		// Timeout also not given, because it is not expected to timeout
	}



	@SuppressWarnings("unused")
	public static void main(String[] args) throws SocketException, IOException, InterruptedException{

		
		log.write("Event\tTime\tType\tSeq\tData_Length\tAck_Num\n".getBytes());
		// Command line arguments
		if (args.length != 14) {
			System.out.println("Missing required arguments. Please run again with required number of arguments");
			System.exit(0);
		}

		String ipAddress = args[0];
		int port = Integer.parseInt(args[1]); 
		String fileName = args[2];
		int maximumWindowSize = Integer.parseInt(args[3]);
		int maximumSegmentSize = Integer.parseInt(args[4]);
		float gamma = Float.parseFloat(args[5]);
		float pDrop = Float.parseFloat(args[6]);
		float pDuplicate = Float.parseFloat(args[7]);
		float pCorrupt = Float.parseFloat(args[8]);
		float pOrder = Float.parseFloat(args[9]);
		int maxOrder = Integer.parseInt(args[10]);
		float pDelay = Float.parseFloat(args[11]);
		int maxDelay = Integer.parseInt(args[12]);
		int seed = Integer.parseInt(args[13]);

		//Convert the file to byte array so it can be divided into packets and sent



		byte[] fileToByteArray = readFileToByteArray(new File(fileName)); 




		DatagramSocket pdfSocket = new DatagramSocket();

		// ESTABLISH CONNECTION



		/*Order of incoming segment
		 * 0) Sequence number
		 * 1) Acknowledgement number
		 * 2) Syn Flag
		 * 3) Ack flag
		 * 4) Fin flag
		 * 5) Data flag
		 * 6) Checksum
		 * 7) Size of payload
		 * 8) Size of header
		 * 9) Actual data	
		 */

		int receiver_sequence = connectionEstablishment(ipAddress, port, pdfSocket);



		InetAddress localhost = InetAddress.getByName(ipAddress);

		Map<Long, byte[]> packets = packetMaker(fileToByteArray, maximumSegmentSize);


		ArrayList<byte[]> testlist = new ArrayList<byte[]> (); //?? What is this?

		long current_key = 0;


		while(!syn_done) {


		}

		for(String temp: data) {
			log.write(temp.getBytes());
			log.write("\n".getBytes());
		}
		
		WrapperClass wrapperObject = 
				new WrapperClass(pdfSocket, packets, current_key,InetAddress.getByName(ipAddress),
						port, seed, maxDelay, (int)(maximumWindowSize/maximumSegmentSize), 
						maxOrder, gamma, pDrop, pDuplicate, pCorrupt, pOrder ,pDelay, log, start_time);
		senderThreadnew thread1 = new senderThreadnew(wrapperObject);
		receiverThread thread2 = new receiverThread(wrapperObject);
		
		thread1.start();
		thread2.start();

		
		thread1.t.join();
		thread2.t.join();
		
		
		Thread.sleep(2000);
		connectionTeardown(ipAddress, port, pdfSocket, packets);	

		pdfSocket.close();


	}	

	static class LogData{

		public long time_difference;
		public String event_name;
		public String packet_type;
		public long sequence_number;
		public long nb_of_bytes;
		public long ack_number;

		public LogData(String event_name, long time_difference, String packet_type, long sequence_number, long nb_of_bytes, long ack_number) {

			this.event_name = event_name;
			this.time_difference = time_difference;
			this.packet_type = packet_type;
			this.sequence_number = sequence_number;
			this.nb_of_bytes = nb_of_bytes;
			this.ack_number = ack_number;

		}

		@Override
		public String toString() {
			return (event_name + "\t" + time_difference + "\t" + packet_type + "\t" + sequence_number + "\t" + nb_of_bytes + "\t" + ack_number);
		}
	}
}

class WrapperClass{

	public ByteArrayOutputStream baos;

	private static DatagramSocket _pdfSocket;
	private static Map<Long, byte[]> _packets;
	private static long _current_key;

	private InetAddress localhost;
	private int port;
	private boolean done = false;

	private float pOrder;
	private float pCorrupt;
	private float pDrop;
	private float pDelay;
	private float pDuplicate;


	//Reorder
	private Boolean waiting_for_reorder = false; //Not waiting yet
	private int maxOrder; //Max number of packets to hold on before sending this one
	private int waitedPackets = 0;


	//Max window size
	private int maximumWindowSize;
	private TreeSet<Long> _sentKeys = new TreeSet<Long>();
	private TreeMap<Long, Long> _timeOut = new TreeMap<Long, Long>();
	private int number_of_packets = 0;



	private long time_before_send = 0;
	private long time_after_send = 0;
	private int seed;
	private int number_of_packets_sent = 0;

	//Fast retransmit
	private TreeMap<Long, Integer> receivedACKS = new TreeMap<Long, Integer>();

	//Timeout variables
	private double alpha = 0.125; //Fixed value for alpha
	private double beta = 0.25;   //Fixed value for beta
	private float gamma;
	private double devRTT = 250;	//Initial value of devRTT
	private double estimatedRTT = 500; //Initial value of estimatedRTT
	private long beforeSend;
	private long afterSend;
	private double timeout = 0;
	private Map<Long, Long> packet_time = new TreeMap<Long, Long>();
	private TreeMap<Long,Long> keysWithTimeout = new TreeMap<Long,Long>();


	private long previous_ack = 0;
	private int countOfPreviousACK = 0;

	//Random
	private Random random;


	//Delay time
	private int delay_time_max;
	private Map<Long,Long> packetsInWindow = new HashMap<Long,Long>();

	//Log stuff
	public int segments_transmitted = 0;
	public int pld_segments = 0;
	public int segments_dropped = 0;
	public int segments_corrupted = 0;
	public int segments_reordered = 0;
	public int segments_duplicated = 0;
	public int segments_delayed = 0;
	public int nb_of_timeoutrxt = 0;
	public int nb_of_fastrxt = 0;
	public int nb_of_dup_ack = 0;
	public long start_time;
	
	public ArrayList<String> data = new ArrayList<String>();
	
	public WrapperClass(DatagramSocket pdfSocket, Map<Long,byte[]> packets, Long current_key, 
			InetAddress localhost, int port, int seed, int delayTime, 
			int MWS, int maxorder, float gamma,float pDrop,float pDuplicate,float pCorrupt,float pOrder ,float pDelay, ByteArrayOutputStream baos, long start_time) {

		set_pdfSocket(pdfSocket);
		set_packets(packets);
		set_current_key(current_key);
		setLocalhost(localhost);
		setPort(port);
		setSeed(seed);
		setRandom(seed);
		setdelaytimemax(delayTime);
		setMWS(MWS);
		setMaxOrder(maxorder);
		initReceivedACKS(packets);
		setGamma(gamma);
		initkeysTimeout();
		this.setpDrop(pDrop);
		this.setpDuplicate(pDuplicate);
		this.setpCorrupt(pCorrupt);
		this.setpOrder(pOrder);
		this.setpDelay(pDelay); 
		this.baos = baos;
		this.start_time = start_time;
	}


	public void putInWindow(long a, long b) {
		this.packetsInWindow.put(a, b);
	}

	public Map<Long,Long> getWindow(){
		return this.packetsInWindow;
	}

	public void removeFromWindow(long a) {
		packetsInWindow.remove(a);
	}

	//Initial timeout
	public void initkeysTimeout() {
		this.keysWithTimeout.put((long)(0 + _packets.get((long)0).length), (long)(500 + gamma*250));
		try {
			//WrapperClass._pdfSocket.setSoTimeout((int)500 + 4*250);
			WrapperClass._pdfSocket.setSoTimeout(0);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	public void putinTimeout(long key, long value) {
		keysWithTimeout.put(key,value);
	}

	public Map<Long,Long> getTimeoutMap() {
		return this.keysWithTimeout;
	}

	public Map<Long,Long> getkeysTimeout() {
		return keysWithTimeout;
	}

	public long returnTimeout(long sampleRTT) {
		this.estimatedRTT = (1-alpha) * estimatedRTT + alpha * sampleRTT;
		this.devRTT = (1-beta) * devRTT + beta * Math.abs(sampleRTT - estimatedRTT);
		return (long) (estimatedRTT + gamma*devRTT);
	}


	public long fastRetransmit() {

		for(long key: receivedACKS.keySet())
			if (receivedACKS.get(key) == 4)
				return key;
		return -99;
	}

	public void initReceivedACKS(Map<Long,byte[]> packets) {

		for (long key: packets.keySet()) 
			receivedACKS.put(key, 0);

	}


	public void putInTreeSet(long key) {
		this._sentKeys.add(key);
	}

	public void removeInTreeSet(long key) {
		this._sentKeys.remove(key);
	}

	public TreeSet<Long> getTreeSet() {
		return this._sentKeys;
	}


	public void setWaitedPackets(int waited) {
		this.waitedPackets = waited;
	}

	public int getWaitedPackets() {
		return this.waitedPackets;
	}

	public void setdelaytimemax(int delayTime) {
		this.delay_time_max = delayTime;
	}

	public int getdelaytimemax() {
		return this.delay_time_max;
	}

	public float getRandom() {
		return random.nextFloat();
	}

	public void setRandom(int seed) {
		random = new Random(seed);
	}

	public int getSeed() {
		return this.seed;
	}

	public void setSeed(int seed) {
		this.seed = seed;
	}

	public Map<Long, byte[]> get_packets() {
		return _packets;
	}
	public void set_packets(Map<Long, byte[]> _packets) {
		WrapperClass._packets = _packets;
	}
	public DatagramSocket get_pdfSocket() {
		return _pdfSocket;
	}
	public void set_pdfSocket(DatagramSocket _pdfSocket) {
		WrapperClass._pdfSocket = _pdfSocket;
	}
	public long get_current_key() {
		return _current_key;
	}
	public void set_current_key(long _current_key) {
		WrapperClass._current_key = _current_key;
	}

	public int getPort() {
		return port;
	}
	public void setPort(int port) {
		this.port = port;
	}
	public InetAddress getLocalhost() {
		return localhost;
	}
	public void setLocalhost(InetAddress localhost) {
		this.localhost = localhost;
	}
	public boolean getBoolean() {
		return this.done;
	}
	public void setBoolean(Boolean bool) {
		this.done = bool;
	}


	public void setReceivedACKs(long key) {
		receivedACKS.put(key, receivedACKS.get(key) + 1);
	}

	public void resetReceivedACKs(long key) {
		receivedACKS.put(key, 0);
	}

	public TreeMap<Long, Integer> getReceivedACKs(){
		return this.receivedACKS;
	}

	public Boolean getWaiting_for_reorder() {
		return waiting_for_reorder;
	}

	public void setWaiting_for_reorder(Boolean waiting_for_reorder) {
		this.waiting_for_reorder = waiting_for_reorder;
	}

	public int getMWS() {
		return maximumWindowSize;
	}

	public void setMWS(int nb_of_packets_to_wait) {
		this.maximumWindowSize = nb_of_packets_to_wait;
	}

	public long getTime_before_send() {
		return time_before_send;
	}

	public void setTime_before_send(long time_before_send) {
		this.time_before_send = time_before_send;
	}

	public long getTime_after_send() {
		return time_after_send;
	}

	public void setTime_after_send(long time_after_send) {
		this.time_after_send = time_after_send;
	}

	public double getTimeout() {
		return timeout;
	}

	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}

	public void incrementPackets() {
		this.setNumber_of_packets_sent(this.getNumber_of_packets_sent() + 1);
	}


	//	public double getRTT() {
	//		this.setEstimatedRTT( (1- this.alpha) * this.getEstimatedRTT());
	//		//this.devRTT = 
	//		return 0;
	//	}

	public long getBeforeSend() {
		return beforeSend;
	}

	public void setBeforeSend(long beforeSend) {
		this.beforeSend = beforeSend;
	}

	public long getAfterSend() {
		return afterSend;
	}

	public void setAfterSend(long afterSend) {
		this.afterSend = afterSend;
	}

	public double getEstimatedRTT() {
		return estimatedRTT;
	}

	public void setEstimatedRTT(double estimatedRTT) {
		this.estimatedRTT = estimatedRTT;
	}

	public double getDevRTT() {
		return devRTT;
	}

	public void setDevRTT(double devRTT) {
		this.devRTT = devRTT;
	}

	public int getNumber_of_packets_sent() {
		return number_of_packets_sent;
	}

	public void setNumber_of_packets_sent(int number_of_packets_sent) {
		this.number_of_packets_sent = number_of_packets_sent;
	}



	public int getMaxOrder() {
		return maxOrder;
	}



	public void setMaxOrder(int maxOrder) {
		this.maxOrder = maxOrder;
	}

	//	public int getPacketsInWindow() {
	//		return packetsInWindow;
	//	}
	//
	//	public void setPacketsInWindow(int packetsSent) {
	//		this.packetsInWindow = packetsSent;
	//	}

	public boolean checkACKS() {

		for (long key: receivedACKS.keySet())
			if(receivedACKS.get(key) == 0)
				return false;

		return true;
	}


	public float getGamma() {
		return gamma;
	}


	public void setGamma(float gamma) {
		this.gamma = gamma;
	}
	//MWS Functions
	public int getNumber_of_packets() {
		return number_of_packets;
	}

	public void setNumber_of_packets(int number_of_packets) {
		//system.out.println(number_of_packets + " number of packets to be set" );
		this.number_of_packets = number_of_packets;
	}

	public float getpOrder() {
		return pOrder;
	}

	public void setpOrder(float pOrder) {
		this.pOrder = pOrder;
	}

	public float getpCorrupt() {
		return pCorrupt;
	}

	public void setpCorrupt(float pCorrupt) {
		this.pCorrupt = pCorrupt;
	}

	public float getpDrop() {
		return pDrop;
	}

	public void setpDrop(float pDrop) {
		this.pDrop = pDrop;
	}

	public float getpDelay() {
		return pDelay;
	}

	public void setpDelay(float pDelay) {
		this.pDelay = pDelay;
	}

	public float getpDuplicate() {
		return pDuplicate;
	}

	public void setpDuplicate(float pDuplicate) {
		this.pDuplicate = pDuplicate;
	}


	public long getPrevious_ack() {
		return previous_ack;
	}


	public void setPrevious_ack(long previous_ack) {
		this.previous_ack = previous_ack;
	}


	public int getCountOfPreviousACK() {
		return countOfPreviousACK;
	}


	public void setCountOfPreviousACK(int count) {
		this.countOfPreviousACK = count;
	}

}



class senderThreadnew implements Runnable{
	
	static class LogData{

		public long time_difference;
		public String event_name;
		public String packet_type;
		public long sequence_number;
		public long nb_of_bytes;
		public long ack_number;

		public LogData(String event_name, long time_difference, String packet_type, long sequence_number, long nb_of_bytes, long ack_number) {

			this.event_name = event_name;
			this.time_difference = time_difference;
			this.packet_type = packet_type;
			this.sequence_number = sequence_number;
			this.nb_of_bytes = nb_of_bytes;
			this.ack_number = ack_number;

		}

		@Override
		public String toString() {
			return (event_name + "\t" + time_difference + "\t" + packet_type + "\t" + sequence_number + "\t" + nb_of_bytes + "\t" + ack_number);
		}
	}
	
	public Thread t;
	WrapperClass wrapperClass;

	private static long getChecksum(byte[] inputFile) {

		long checksum = 0;
		for (byte b: inputFile)
			checksum+= (int)b;

		return checksum;				
	}


	private static byte[] corruptBit(byte[] inputFile) {

		byte[] test = new byte[inputFile.length]; 
		System.arraycopy(inputFile, 0, test, 0, inputFile.length);
		if (test[inputFile.length/2] == 0)
			test[inputFile.length/2] = 127;
		else
			test[inputFile.length/2] = 0; 
		return test;
	}



	senderThreadnew(WrapperClass wrapperClass){

		this.wrapperClass = wrapperClass;
	}

	@Override
	public void run(){
		try {
			wrapperClass.get_pdfSocket().setSoTimeout(0);
		} catch (SocketException e2) {
			e2.printStackTrace();
		}
		DatagramPacket reorderedpacket = null;
		for(long key: wrapperClass.get_packets().keySet()) {

			wrapperClass.data.add(new LogData("snd", System.currentTimeMillis() - wrapperClass.start_time, "D", key+1 , 0, 1).toString());
//			if(wrapperClass.getWaiting_for_reorder()) {
//				if(wrapperClass.getWaitedPackets() == wrapperClass.getMaxOrder()) {
//					System.out.println("SENDING REORDERED PACKET OI");
//					wrapperClass.setWaitedPackets(0);
//					wrapperClass.setWaiting_for_reorder(false);
//					try {
//						wrapperClass.get_pdfSocket().send(reorderedpacket);
//						
//					} catch (IOException e) {
//						
//						e.printStackTrace();
//					}
//
//				}else {
//					wrapperClass.setWaitedPackets(wrapperClass.getWaitedPackets() + 1);
//					System.out.println(wrapperClass.getWaitedPackets() + " packets waited");
//				}
//					
//			}

			
			
			//system.out.println("MWS " + wrapperClass.getMWS() + " no of packs in window " + wrapperClass.getNumber_of_packets());
			while(true) {

				if((wrapperClass.getNumber_of_packets() < wrapperClass.getMWS()))
					break;
				else {
					//System.out.println("waiting");
					try {
						Thread.sleep(1);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					//break;
				}
					
			}
			
			
			
			
			//wrapperClass.putinTimeout(key + wrapperClass.get_packets().get(key).length, System.currentTimeMillis());
			
			
			
			Long checksumForPacket = getChecksum(wrapperClass.get_packets().get(key));

			
			String message = key+"\n0000\nF\nF\nF\nT\n"+ checksumForPacket + "\n"+wrapperClass.get_packets().get(key).length+"\n";


			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			String testing = message.getBytes().length + "\n";


			try {
				outputStream.write(message.getBytes());
				outputStream.write(testing.getBytes());
				outputStream.write(wrapperClass.get_packets().get(key));
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}

			byte[] packet = outputStream.toByteArray();


			try {
				outputStream.flush();
				outputStream.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}

			if(wrapperClass.getRandom() < wrapperClass.getpDrop()) {
				//DO NOTHING BECAUSE DROPPED
				wrapperClass.segments_dropped++;
				wrapperClass.pld_segments++;
				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				try {
					wrapperClass.get_pdfSocket().send(sending);
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
			}
			if(wrapperClass.getRandom() < wrapperClass.getpCorrupt()) {
				//CORRUPT!

				wrapperClass.segments_corrupted++;
				wrapperClass.pld_segments++;
				
				String corrupt_message = key+"\n0000\nF\nF\nF\nT\n"+ checksumForPacket + "\n"+wrapperClass.get_packets().get(key).length+"\n";


//				ByteArrayOutputStream corrupt_outputStream = new ByteArrayOutputStream();
//				String corrupt_testing = message.getBytes().length + "\n";
//
//				byte[] corrupt_packet = corruptBit(wrapperClass.get_packets().get(key));	
//				try {
//					corrupt_outputStream.write(corrupt_message.getBytes());
//					corrupt_outputStream.write(corrupt_testing.getBytes());
//					corrupt_outputStream.write(corrupt_packet);
//				} catch (IOException e1) {
//					// TODO Auto-generated catch block
//					System.out.println("Exception " +  key);
//				}
//
//				byte[] corrupt_packet_send = corrupt_outputStream.toByteArray();
//
//
//				try {
//					corrupt_outputStream.flush();
//					corrupt_outputStream.close();
//				} catch (IOException e) {
//					// TODO Auto-generated catch block
//					System.out.println("Exception " +  key);
//				}
//
//				DatagramPacket sending = new DatagramPacket(corrupt_packet_send, corrupt_packet_send.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
//				try {
//					wrapperClass.get_pdfSocket().send(sending);
//					//wrapperClass.get_pdfSocket().setSoTimeout(0); 
//				} catch (IOException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
			
				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				try {
					wrapperClass.get_pdfSocket().send(sending);
					
			 
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
			
			}else if(wrapperClass.getRandom() < wrapperClass.getpOrder()) {
				
				wrapperClass.segments_reordered++;
				wrapperClass.pld_segments++;
			}
			else if(wrapperClass.getRandom() < wrapperClass.getpDuplicate()) {
				//DUPLICATED
				
				wrapperClass.segments_duplicated++;
				wrapperClass.pld_segments++;
				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				try {
					wrapperClass.get_pdfSocket().send(sending);
					wrapperClass.get_pdfSocket().send(sending);
			 
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
			}
//			else if(wrapperClass.getRandom() < wrapperClass.getpOrder()){
//				//REORDER
//				//system.out.println("Git reodered" + key);
//
//				if(wrapperClass.getWaiting_for_reorder()) {
//					//system.out.println("Got reordered but getting sent" + key);
//					DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
//					try {
//						wrapperClass.get_pdfSocket().send(sending);
//			
//					} catch (IOException e) {
//						// 
//						e.printStackTrace();
//					}
//				}else {
//					
//					reorderedpacket = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());	
//					wrapperClass.setWaiting_for_reorder(true);
//
//				}
//			}	
			else if(wrapperClass.getRandom() < wrapperClass.getpDelay()){
				//DELAY
				//system.out.println("Git delayed " + key);
				wrapperClass.segments_delayed++;
				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				wrapperClass.pld_segments++;
				WaitThread delay = new WaitThread(wrapperClass, sending, key);
				delay.start();
			}
			else {

				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				try {
					wrapperClass.get_pdfSocket().send(sending);
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			wrapperClass.setNumber_of_packets( (wrapperClass.getNumber_of_packets() + 1) );
			wrapperClass.segments_transmitted++;
			
		}

	}

	public void start() {

		t = new Thread(this);
		t.start();
	}

}














class senderThread implements Runnable {

	private static long getChecksum(byte[] inputFile) {

		long checksum = 0;
		for (byte b: inputFile)
			checksum+= (int)b;

		return checksum;				
	}


	private static byte[] corruptBit(byte[] inputFile) {

		byte[] test = new byte[inputFile.length]; 
		System.arraycopy(inputFile, 0, test, 0, inputFile.length);
		if (test[inputFile.length] == 0)
			test[inputFile.length/2] = 127;
		else
			test[inputFile.length/2] = 0; 
		return test;
	}


	public Thread t;
	WrapperClass wrapperClass;

	senderThread(WrapperClass wrapperClass){

		this.wrapperClass = wrapperClass;
	}

	@Override
	public void run(){
		// TODO Auto-generated method stub
		//System.out.println("Entered thread");
		DatagramPacket reorderedPacket = null;
		Long reorderedKey = null;
		try {
			wrapperClass.get_pdfSocket().setSoTimeout(0);
		} catch (SocketException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		for(long key: wrapperClass.get_packets().keySet()) {

			//system.out.println("window size: " + wrapperClass.getNumber_of_packets() + " MWS: " + wrapperClass.getMWS());
			while(true) {

				if((wrapperClass.getNumber_of_packets() < wrapperClass.getMWS()))
					break;
				//				else
				//					System.out.println("Waiting");
			}


			wrapperClass.setNumber_of_packets( (wrapperClass.getNumber_of_packets() + 1) );
			wrapperClass.putInWindow(wrapperClass.get_packets().get(key).length + key, key);
			wrapperClass.putinTimeout(key + wrapperClass.get_packets().get(key).length, System.currentTimeMillis());

			if(wrapperClass.getWaiting_for_reorder()) {
				if(wrapperClass.getWaitedPackets() == wrapperClass.getMaxOrder()) {
					//system.out.println("SENDING REORDERED PACKET OI");
					wrapperClass.setWaitedPackets(0);
					wrapperClass.setWaiting_for_reorder(false);
					try {
						wrapperClass.get_pdfSocket().send(reorderedPacket);
						//wrapperClass.set_sentKeys(key);
						//wrapperClass.get_pdfSocket().setSoTimeout(0); 
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

				}else
					wrapperClass.setWaitedPackets(wrapperClass.getWaitedPackets() + 1);
			}
			//System.out.println("Sending key " +  key);
			Long checksumForPacket = getChecksum(wrapperClass.get_packets().get(key));


			String message = key+"\n0000\nF\nF\nF\nT\n"+ checksumForPacket + "\n"+wrapperClass.get_packets().get(key).length+"\n";


			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			String testing = message.getBytes().length + "\n";


			try {
				outputStream.write(message.getBytes());
				outputStream.write(testing.getBytes());
				outputStream.write(wrapperClass.get_packets().get(key));
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}

			byte[] packet = outputStream.toByteArray();


			try {
				outputStream.flush();
				outputStream.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}


			if(wrapperClass.getRandom() < wrapperClass.getpDrop()) {
				//DO NOTHING BECAUSE DROPPED
				//wrapperClass.putInTreeSet(key + wrapperClass.get_packets().get(key).length);
				//System.out.println("Git dropped");
			}else if(wrapperClass.getRandom() < wrapperClass.getpDuplicate()) {
				//DUPLICATED
				//wrapperClass.putInTreeSet(key + wrapperClass.get_packets().get(key).length);
				//system.out.println("Git duplicated");
				//wrapperClass.putinTimeout(key + wrapperClass.get_packets().get(key).length, System.currentTimeMillis());
				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				try {
					wrapperClass.get_pdfSocket().send(sending);
					wrapperClass.get_pdfSocket().send(sending);
					//wrapperClass.get_pdfSocket().setSoTimeout(100); 
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	

			}else if(wrapperClass.getRandom() < wrapperClass.getpCorrupt()) {
				//CORRUPT!

				//wrapperClass.putInTreeSet(key + wrapperClass.get_packets().get(key).length);

				//system.out.println("Git corrupted");
				String corrupt_message = key+"\n0000\nF\nF\nF\nT\n"+ checksumForPacket + "\n"+wrapperClass.get_packets().get(key).length+"\n";


				ByteArrayOutputStream corrupt_outputStream = new ByteArrayOutputStream();
				String corrupt_testing = message.getBytes().length + "\n";

				byte[] corrupt_packet = corruptBit(wrapperClass.get_packets().get(key));	
				try {
					outputStream.write(corrupt_message.getBytes());
					outputStream.write(corrupt_testing.getBytes());
					outputStream.write(corrupt_packet);
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					System.out.println("Exception " +  key);
				}

				byte[] corrupt_packet_send = corrupt_outputStream.toByteArray();


				try {
					corrupt_outputStream.flush();
					corrupt_outputStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.out.println("Exception " +  key);
				}

				DatagramPacket sending = new DatagramPacket(corrupt_packet_send, corrupt_packet_send.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				try {
					wrapperClass.get_pdfSocket().send(sending);
					//wrapperClass.get_pdfSocket().setSoTimeout(0); 
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}


			}else if(wrapperClass.getRandom() < wrapperClass.getpOrder()){
				//REORDER
				//system.out.println("Git reodered");
				if(wrapperClass.getWaiting_for_reorder()) {
					DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
					try {
						wrapperClass.get_pdfSocket().send(sending);
						//wrapperClass.set_sentKeys(key);
						//wrapperClass.putInTreeSet(key + wrapperClass.get_packets().get(key).length);
						//wrapperClass.get_pdfSocket().setSoTimeout(0); 
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}else {
					reorderedPacket = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
					//reorderedKey = key + wrapperClass.get_packets().get(key).length;
					wrapperClass.setWaiting_for_reorder(true);

				}

			}else if(wrapperClass.getRandom() < wrapperClass.getpDelay()){
				//DELAY
				//system.out.println("Git delayed");
				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				//wrapperClass.putinTimeout(key + wrapperClass.get_packets().get(key).length, System.currentTimeMillis());
				WaitThread delay = new WaitThread(wrapperClass, sending, key);
				delay.start();
			}else {
				//system.out.println("Git going");
				//wrapperClass.putinTimeout(key + wrapperClass.get_packets().get(key).length, System.currentTimeMillis());
				//wrapperClass.putInTreeSet(key + wrapperClass.get_packets().get(key).length);
				DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
				try {
					wrapperClass.get_pdfSocket().send(sending);
					//wrapperClass.set_sentKeys(key);
					//wrapperClass.get_pdfSocket().setSoTimeout(0); 
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

		}	

	}

	public void start() {
		t = new Thread(this);
		t.start();
	}

}

class receiverThread implements Runnable{
	
	static class LogData{

		public long time_difference;
		public String event_name;
		public String packet_type;
		public long sequence_number;
		public long nb_of_bytes;
		public long ack_number;

		public LogData(String event_name, long time_difference, String packet_type, long sequence_number, long nb_of_bytes, long ack_number) {

			this.event_name = event_name;
			this.time_difference = time_difference;
			this.packet_type = packet_type;
			this.sequence_number = sequence_number;
			this.nb_of_bytes = nb_of_bytes;
			this.ack_number = ack_number;

		}

		@Override
		public String toString() {
			return (event_name + "\t" + time_difference + "\t" + packet_type + "\t" + sequence_number + "\t" + nb_of_bytes + "\t" + ack_number);
		}
	}
	
	public Thread t;
	private WrapperClass wrapperClass;

	//Constructor
	receiverThread(WrapperClass wrapperClass){

		this.wrapperClass = wrapperClass;
	}


	@Override
	public void run() {

		while(true) {

			DatagramPacket receive_ack = new DatagramPacket(new byte[64000], 64000);
			
				if(wrapperClass.getCountOfPreviousACK() == 3) {
					ResendThread resend = new ResendThread(wrapperClass, wrapperClass.getPrevious_ack());
					resend.start();
					try {
						resend.t.join();
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			
				try {
					wrapperClass.get_pdfSocket().receive(receive_ack);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				wrapperClass.setNumber_of_packets( wrapperClass.getNumber_of_packets() - 1 );
				
				String response_string = null;
				
				try {
					response_string = new String(receive_ack.getData(), "ISO-8859-1");
				} catch (UnsupportedEncodingException e1) {

					e1.printStackTrace();
				}
				//wrapperClass.setNumber_of_packets( (wrapperClass.getNumber_of_packets() - 1) );
				String[] received_response = response_string.split("\\n");
				Long received_ack = Long.parseLong(received_response[1]);
				wrapperClass.removeFromWindow(received_ack);
				wrapperClass.data.add(new LogData("rcv", System.currentTimeMillis() - wrapperClass.start_time, "D", received_ack , 0, Long.parseLong(received_response[1])).toString());
				if (wrapperClass.get_packets().get(received_ack) == null)
					break;

				if (received_ack == wrapperClass.getPrevious_ack()) {
					wrapperClass.setCountOfPreviousACK(wrapperClass.getCountOfPreviousACK() + 1);
					wrapperClass.nb_of_dup_ack++;
				}
				else {
					
					//System.out.println(wrapperClass.getNumber_of_packets() + " windowed packs");
					
					
					wrapperClass.setCountOfPreviousACK(0);
					wrapperClass.setPrevious_ack(received_ack);

					}				
				}
//		for(long key: wrapperClass.getReceivedACKs().keySet()) 
//			System.out.println(key + " " + wrapperClass.getReceivedACKs().get(key));

		for(String key: wrapperClass.data) {
			try {
				wrapperClass.baos.write(key.getBytes());
				wrapperClass.baos.write("\n".getBytes());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		try {
			wrapperClass.baos.write("======================\n".getBytes());
			wrapperClass.baos.write(("Size of the file in bytes\t " + wrapperClass.getPrevious_ack() + "\n").getBytes());
			wrapperClass.baos.write(("Segments transmitted\t " + wrapperClass.segments_transmitted+ "\n").getBytes());
			wrapperClass.baos.write(("Segments handled by PLD\t " + wrapperClass.pld_segments+ "\n").getBytes());
			wrapperClass.baos.write(("Segments dropped\t " + wrapperClass.segments_dropped+ "\n").getBytes());
			wrapperClass.baos.write(("Segments Corrupted\t" + wrapperClass.segments_corrupted+ "\n").getBytes());
			wrapperClass.baos.write(("Segments Re-ordered\t" + wrapperClass.segments_reordered+ "\n").getBytes());
			wrapperClass.baos.write(("Segments Duplicated\t" + wrapperClass.segments_duplicated+ "\n").getBytes());
			wrapperClass.baos.write(("Segments Delayed\t" + wrapperClass.segments_delayed+ "\n").getBytes());
			wrapperClass.baos.write(("Segments RXT due to timeout\t" + 0+ "\n").getBytes());
			wrapperClass.baos.write(("Segments Fast RXT\t" + wrapperClass.nb_of_fastrxt+ "\n").getBytes());
			wrapperClass.baos.write(("Duplicate ACKs received\t" + wrapperClass.nb_of_dup_ack+ "\n").getBytes());
		}catch(IOException e1) {
			e1.printStackTrace();
		}
	
		byte[] log_file_contents = wrapperClass.baos.toByteArray();
		try {
			wrapperClass.baos.flush();
			wrapperClass.baos.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		File log_file = new File("sender_log.txt");
		try {
			log_file.createNewFile();
			FileOutputStream fileStream = new FileOutputStream(log_file);
			fileStream.write(log_file_contents);
			fileStream.flush();
			fileStream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public void start() {
		t = new Thread(this);
		t.start();
	}
}



class ResendThread implements Runnable{

	static class LogData{

		public long time_difference;
		public String event_name;
		public String packet_type;
		public long sequence_number;
		public long nb_of_bytes;
		public long ack_number;

		public LogData(String event_name, long time_difference, String packet_type, long sequence_number, long nb_of_bytes, long ack_number) {

			this.event_name = event_name;
			this.time_difference = time_difference;
			this.packet_type = packet_type;
			this.sequence_number = sequence_number;
			this.nb_of_bytes = nb_of_bytes;
			this.ack_number = ack_number;

		}

		@Override
		public String toString() {
			return (event_name + "\t" + time_difference + "\t" + packet_type + "\t" + sequence_number + "\t" + nb_of_bytes + "\t" + ack_number);
		}
	}
	private static long getChecksum(byte[] inputFile) {

		long checksum = 0;
		for (byte b: inputFile)
			checksum+= (int)b;

		return checksum;				
	}

	public Thread t;

	private long key;
	private WrapperClass wrapperClass;
	public ResendThread(WrapperClass wrapperClass, long key) {


		this.wrapperClass = wrapperClass;
		this.key = key;
	}

	public ResendThread(WrapperClass wrapperClass) {

		this.wrapperClass = wrapperClass;
		this.key = -99;

	}

	@Override
	public void run() {



		if(key==-99) {
			Long find_key = null;
			//system.out.println("Timeoutthread");
			for(long temp: wrapperClass.getWindow().keySet()) {
				find_key = temp;
				break;
			}
			key = find_key;
			//system.out.println("key:" + key);
			Long checksumForPacket = getChecksum(wrapperClass.get_packets().get(key));


			String message = key+"\n0000\nF\nF\nF\nT\n"+ checksumForPacket + "\n"+wrapperClass.get_packets().get(key).length+"\n";

			//wrapperClass.resetReceivedACKs(key);
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			String testing = message.getBytes().length + "\n";


			try {
				outputStream.write(message.getBytes());
				outputStream.write(testing.getBytes());
				outputStream.write(wrapperClass.get_packets().get(key));
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}

			byte[] packet = outputStream.toByteArray();


			try {
				outputStream.flush();
				outputStream.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}

			DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
			try {
				wrapperClass.get_pdfSocket().send(sending); 
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		

		}

		else {
			//system.out.println("fast retransmit thread invoked");
			wrapperClass.data.add(new LogData("snd", System.currentTimeMillis() - wrapperClass.start_time, "D", key+1 , 0, 1).toString());
			wrapperClass.nb_of_fastrxt++;
			//system.out.println(":" + key);
			Long checksumForPacket = getChecksum(wrapperClass.get_packets().get(key));


			String message = key+"\n0000\nF\nF\nF\nT\n"+ checksumForPacket + "\n"+wrapperClass.get_packets().get(key).length+"\n";

			//wrapperClass.resetReceivedACKs(key);
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			String testing = message.getBytes().length + "\n";


			try {
				outputStream.write(message.getBytes());
				outputStream.write(testing.getBytes());
				outputStream.write(wrapperClass.get_packets().get(key));
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}

			byte[] packet = outputStream.toByteArray();


			try {
				outputStream.flush();
				outputStream.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("Exception " +  key);
			}

			DatagramPacket sending = new DatagramPacket(packet, packet.length, wrapperClass.getLocalhost(),wrapperClass.getPort());
			try {
				wrapperClass.get_pdfSocket().send(sending); 
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		
		}
	}

	public void start() {
		t = new Thread(this);
		t.start();

	}
}



class WaitThread implements Runnable{

	public Thread t;
	private WrapperClass wrapperClass;
	private DatagramPacket delayPacket;
	private long key;
	public WaitThread(WrapperClass wrapperClass, DatagramPacket delayPacket, long key) {

		this.wrapperClass = wrapperClass;
		this.delayPacket = delayPacket;
		this.key = key;
	}

	@Override
	public void run() {

		try {
			//Thread.sleep(200);
			Thread.sleep((long)ThreadLocalRandom.current().nextInt(0, wrapperClass.getdelaytimemax()));
		}catch(InterruptedException exception) {
			exception.printStackTrace();
		}

		try {
			wrapperClass.get_pdfSocket().send(delayPacket);
			//wrapperClass.putInTreeSet(key + wrapperClass.get_packets().get(key).length);
			//wrapperClass.set_sentKeys(key);
		} catch(SocketException exception) {
			exception.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}

	public void start() {

		t = new Thread(this);
		t.start();

	}

}


