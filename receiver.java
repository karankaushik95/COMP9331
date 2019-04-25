/*
 * Written by Karan Kaushik for COMP9331
 * Computer Networks - 18s2
 * 
 * */

import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;


public class receiver {



	public static ArrayList<LogData> write_to_log = new ArrayList<LogData>();
	static long start_time = System.currentTimeMillis();

	public static ArrayList<Long> packets_received = new ArrayList<Long>();


	private static long getChecksum(byte[] inputFile) {

		long checksum = 0;
		for (byte b: inputFile)
			checksum+= b;

		return checksum;		


	}

	/*
	 * assembleFile takes the data received from the socket and reassembles it
	 * using a FileOutputStream
	 * 
	 * */

	public static void assembleFile(String filename, Map<Long, byte[]> packets) throws IOException{

		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();


		for (Long entry : packets.keySet()) 
			byteStream.write(packets.get(entry));

		
		byte[] final_file_contents = byteStream.toByteArray();
		byteStream.flush();
		byteStream.close();

		File output_file = new File(filename);
		output_file.createNewFile();
		FileOutputStream fileStream = new FileOutputStream(output_file);
		fileStream.write(final_file_contents);
		fileStream.flush();
		fileStream.close();

	}
	@SuppressWarnings("unused")
	public static void main(String[] args) throws SocketException, IOException{

		ByteArrayOutputStream log = new ByteArrayOutputStream();

		log.write("Event\tTime\tType\tSeq\tData_Length\tAck_Num\n".getBytes());
		

		packets_received.add((long) 0);
		int port = Integer.parseInt(args[0]);
		String filename = args[1];
		Map<Long, byte[]> packets = new TreeMap<Long, byte[]>(); 

		List<String> data = new ArrayList<String>();

		boolean FIN = false;
		boolean corrupted = false;
		boolean SYN = false;
		long receiver_sequence_number = 0; 


		long expected_sequence_number = 0; 
		long avg_packet_length;


		long totalReceivedData = 0;
		int totalPacketsReceived = 0;
		int totalDataPacketsReceived = 0;
		int totalCorruptedPacketsReceived = 0;
		int duplicateDataSegmentsReceived = 0;
		int duplicateAcksSent = 0;

		DatagramSocket socket = new DatagramSocket(port);


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

		while (true) {


			DatagramPacket request = new DatagramPacket(new byte[64000], 64000); //Maximum allowed size of udp

			socket.receive(request);
			totalPacketsReceived++;

			
			String temp_string = new String(request.getData(), "ISO-8859-1");
			String[] received_response = temp_string.split("\\n");

			//Setting up TCP Connection
			if (received_response[2].contains("T")) {
				

				data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "S", Long.parseLong(received_response[0]), 0, receiver_sequence_number).toString());
				InetAddress clientHost = request.getAddress();
				int clientPort = request.getPort();
				
				String message = receiver_sequence_number + "\n" + received_response[0]+1 + "\n" + "T\nT\nF\nF\n";
				DatagramPacket reply = new DatagramPacket(message.getBytes(), message.length(), clientHost, clientPort);
				SYN = true;
				data.add(new LogData("snd", System.currentTimeMillis() - start_time, "SA", receiver_sequence_number, 0, Long.parseLong(received_response[0]) + 1).toString());
			
				socket.send(reply);
				receiver_sequence_number++;
			}
			//Teardown
			else if(received_response[4].contains("T")) {

				data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "F", Long.parseLong(received_response[0]), 0, receiver_sequence_number).toString());
				InetAddress clientHost = request.getAddress();
				int clientPort = request.getPort();
				
				String message = receiver_sequence_number + "\n" + received_response[0]+1 + "\n" + "F\nT\nF\nF\n";
				DatagramPacket reply = new DatagramPacket(message.getBytes(), message.length(), clientHost, clientPort);
				socket.send(reply);
				data.add(new LogData("snd", System.currentTimeMillis() - start_time, "A", receiver_sequence_number, 0, Long.parseLong(received_response[0]) + 1).toString());

				FIN = true;
				
				String receiverFIN = receiver_sequence_number + "\n" + received_response[0]+1 + "\n" + "F\nF\nT\nF\n";
				DatagramPacket receiverFINPacket = new DatagramPacket(receiverFIN.getBytes(), receiverFIN.length(), clientHost, clientPort);
				data.add(new LogData("snd", System.currentTimeMillis() - start_time, "F", receiver_sequence_number, 0, Long.parseLong(received_response[0]) + 1).toString());
				socket.send(receiverFINPacket);

			}
			//SYN-ACK receiving
			else if(received_response[3].contains("T")) {
				
				if (SYN) {
					SYN = false;
				
					data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "A", Long.parseLong(received_response[0]), 0, receiver_sequence_number).toString());
				
				}
				// Teardown
				else if (FIN) {
				
					data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "A", Long.parseLong(received_response[0]), 0, receiver_sequence_number).toString());
					break;
				}

			}else if (received_response[5].contains("T")){

				



				totalDataPacketsReceived++;


				byte[] receivedData = Arrays.copyOfRange(request.getData(), Integer.parseInt(received_response[8]) + 3, Integer.parseInt(received_response[8]) + Integer.parseInt(received_response[7]) + 3);
			

				Long destinationChecksum = getChecksum(receivedData);
				if (destinationChecksum != Long.parseLong(received_response[6])) {
					corrupted = true;
					totalCorruptedPacketsReceived++;
			
					data.add(new LogData("rcv/corr", System.currentTimeMillis() - start_time, "D", Long.parseLong(received_response[0]) +1, 0, receiver_sequence_number).toString());	
				}
				else {
					if(!(packets_received.contains(Long.parseLong(received_response[0]) + Long.parseLong(received_response[7]))))
						packets_received.add(Long.parseLong(received_response[0]) + Long.parseLong(received_response[7]));
			

					if(packets.containsKey(Long.parseLong(received_response[0]))) {
						data.add(new LogData("rcv/dup", System.currentTimeMillis() - start_time, "D", Long.parseLong(received_response[0]) +1, receivedData.length, receiver_sequence_number).toString());
						duplicateDataSegmentsReceived++;
					}
					else
						data.add(new LogData("rcv", System.currentTimeMillis() - start_time, "D", Long.parseLong(received_response[0])+1, receivedData.length, receiver_sequence_number).toString());

				}

			



				if (!corrupted) {
					avg_packet_length = receivedData.length;	
					totalReceivedData += receivedData.length;
				
					packets.put(Long.parseLong(received_response[0]), receivedData);
					InetAddress clientHost = request.getAddress();
					int clientPort = request.getPort();

					if (Long.parseLong(received_response[0]) != packets_received.get(0)) {
	
						String reply_string = receiver_sequence_number+"\n"+packets_received.get(0)+"\nF\nT\nF\n";
						DatagramPacket reply = new DatagramPacket(reply_string.getBytes(), reply_string.length(), clientHost, clientPort);
						expected_sequence_number = (Long.parseLong(received_response[0])+receivedData.length);
						data.add(new LogData("snd/DA", System.currentTimeMillis() - start_time, "A", receiver_sequence_number, 0, packets_received.get(0)).toString());
						socket.send(reply);
						duplicateAcksSent++;
									
					}
					else {
						packets_received.remove(0);
						long find_key = -99;
						for(long key: packets.keySet()) 
							if (key>find_key)
								find_key = key;
			
						data.add(new LogData("snd", System.currentTimeMillis() - start_time, "A", receiver_sequence_number, 0, find_key + receivedData.length).toString());
						String reply_string = receiver_sequence_number+"\n"+(find_key+receivedData.length)+"\nF\nT\nF\n";
						


						expected_sequence_number = (find_key+receivedData.length);
						DatagramPacket reply = new DatagramPacket(reply_string.getBytes(), reply_string.length(), clientHost, clientPort);
						socket.send(reply);
						receiver_sequence_number++;
			

					}
				}
				else {

		
					corrupted = false;
				}


			}


		}

		assembleFile(filename, packets);
		
		
		for(String line: data) {
			log.write(line.getBytes());
			log.write("\n".getBytes());
		}
		
		
		log.write("=========================================\n".getBytes());
		
		List<String> text = new ArrayList<String>();
		log.write("Amount of data received(bytes):\t".concat(String.valueOf(totalReceivedData)).concat("\n").getBytes());
		log.write("Total Segments received:\t".concat(String.valueOf(totalPacketsReceived)).concat("\n").getBytes());
		log.write("Data Segments received:\t".concat(String.valueOf(totalDataPacketsReceived)).concat("\n").getBytes());
		log.write("Data Segments received with bit error:\t".concat(String.valueOf(totalCorruptedPacketsReceived)).concat("\n").getBytes());
		log.write("Duplicate Data Segments received:\t".concat(String.valueOf(duplicateDataSegmentsReceived)).concat("\n").getBytes());
		log.write("Duplicate ACKS sent:\t".concat(String.valueOf(duplicateAcksSent)).concat("\n").getBytes());
//		Files.write(file, text, Charset.forName("UTF-8"));
		
		byte[] log_file_contents = log.toByteArray();
		log.flush();
		log.close();
		
		
		File log_file = new File("receiver_log.txt");
		log_file.createNewFile();
		FileOutputStream fileStream = new FileOutputStream(log_file);
		fileStream.write(log_file_contents);
		fileStream.flush();
		fileStream.close();
//		

		
		
		
		
		socket.close();


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
