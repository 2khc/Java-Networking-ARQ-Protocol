/*
 *  (c) K.Bryson, Dept. of Computer Science, UCL (2016)
 *  
 *  YOU MAY MODIFY THIS CLASS TO IMPLEMENT Stop & Wait ARQ PROTOCOL.
 *  (You will submit this class to Moodle.)
 *
 */

package physical_network;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;


/**
 * Represents a network card that can be attached to a particular wire.
 * <p>
 * It has only two key responsibilities:
 * i) Allow the sending of data frames consisting of arrays of bytes using send() method.
 * ii) Receives data frames into an input queue with a receive() method to access them.
 *
 * @author K. Bryson
 */

public class NetworkCard {

    // Wire pair that the network card is atatched to.
    private final TwistedWirePair wire;

    // Unique device number and name given to the network card.
    private final int deviceNumber;
    private final String deviceName;

    // Default values for high, low and mid- voltages on the wire.
    private final double HIGH_VOLTAGE = 2.5;
    private final double LOW_VOLTAGE = -2.5;

    // Default value for a signal pulse width that should be used in milliseconds.
    private final int PULSE_WIDTH = 200;

    // Default value for maximum payload size in bytes.
    private final int MAX_PAYLOAD_SIZE = 1500;

    // Default value for input & output queue sizes.
    private final int QUEUE_SIZE = 5;

    // Output queue for dataframes being transmitted.
    private LinkedBlockingQueue<DataFrame> outputQueue = new LinkedBlockingQueue<DataFrame>(QUEUE_SIZE);

    // Input queue for dataframes being received.
    private LinkedBlockingQueue<DataFrame> inputQueue = new LinkedBlockingQueue<DataFrame>(QUEUE_SIZE);

    // Transmitter thread.
    private Thread txThread;

    // Receiver thread.
    private Thread rxThread;

    private byte[] ackReceived = {0x7E, 0x7E, 0x7E};

    private int numOfMessagesSent = 0;

    private double thresholdVoltage;

    /**
     * NetworkCard constructor.
     *
     * @param deviceName This provides the name of this device, i.e. "Network Card A".
     * @param wire       This is the shared wire that this network card is connected to.
     * @param listener   A data frame listener that should be informed when data frames are received.
     *                   (May be set to 'null' if network card should not respond to data frames.)
     */
    public NetworkCard(int number, TwistedWirePair wire) {

        this.deviceNumber = number;
        this.deviceName = "NetCard" + number;
        this.wire = wire;

        txThread = this.new TXThread();
        rxThread = this.new RXThread();
    }

    /*
     * Initialize the network card.
     */
    public void init() {
        txThread.start();
        rxThread.start();
        thresholdVoltage = (LOW_VOLTAGE + 2.0 * HIGH_VOLTAGE) / 3.0;
    }


    public void send(DataFrame data) throws InterruptedException {

        outputQueue.put(data);
    }


    public DataFrame receive() throws InterruptedException {
        DataFrame data = inputQueue.take();
        return data;
    }

    /*
     * Private inner thread class that transmits data.
     */
    private class TXThread extends Thread {

        public void run() {

            try {
                while (true) {
                    int sleepTime = 15000;

                    // Get DataFrame from outputQueue to transmit.
                    // Also check if frame is an ACK, before we decide to process it or not.
                    DataFrame frame = outputQueue.take();
                    DataFrame packet;

                    if (frame.getPayload().length == 3) {

                        System.out.println("This is an ACK packet.");

                        transmitFrame(frame);

                    } else {
                        // Create packet to send, and assign it an ID.
                        packet = createPacket(frame, numOfMessagesSent);
                        int packetId = numOfMessagesSent;
                        transmitFrame(packet);
                        numOfMessagesSent++;
//                        double num = 0.0;
                        while (true) {
                            System.out.println("Waiting for ACK.");
                            sleep(sleepTime);

                            // For reference, ackReceived[0] =dest
                            // ackReceived[1] = source
                            // ackReceived[2] = packetId
                            if (ackReceived[0] == packet.payload[4] && ackReceived[2] == packet.payload[5]) {
                                System.out.println("Received confirmation from netCard: " + ackReceived[1]);

                                break;
                            } else if ((ackReceived[0] & 0xFF) == 0x7E) {
                                System.out.println("No confirmation received, retransmitting.");
//                                num += 0.2;
                                thresholdVoltage += 0.1;
                                System.out.println("tresholdVoltage raised to: " + thresholdVoltage);

                                transmitFrame(packet);
                            }

                        }
                    }
                }
            } catch (InterruptedException except) {
                System.out.println(deviceName + " Transmitter Thread Interrupted - terminated.");
            }

        }

        /**
         * Tell the network card to send this data frame across the wire.
         * NOTE - THIS METHOD ONLY RETURNS ONCE IT HAS TRANSMITTED THE DATA FRAME.
         *
         * @param frame Data frame to transmit across the network.
         */
        public void transmitFrame(DataFrame frame) throws InterruptedException {

            // Attempt to eliminate noise before transmitting the frame.


            if (frame != null) {

                // Low voltage signal to get ready ...
                wire.setVoltage(deviceName, LOW_VOLTAGE);
                sleep(PULSE_WIDTH * 4);

                byte[] packet = frame.getTransmittedBytes();

                // Now we can transmit our whole packet!
                // Send bytes in asynchronous style with 0.2 seconds gaps between them.
                for (int i = 0; i < packet.length; i++) {

                    // Byte stuff if required.
                    if (packet[i] == 0x7E || packet[i] == 0x7D)
                        transmitByte((byte) 0x7D);

                    transmitByte(packet[i]);
                }

                // Append a 0x7E to terminate frame.
                transmitByte((byte) 0x7E);
                wire.setVoltage(deviceName, 0.0);
            }
        }

        private void transmitAck(DataFrame frame) throws InterruptedException {

            if (frame != null) {
                System.out.println("This is an ACK frame");
            }

        }

        private void transmitByte(byte value) throws InterruptedException {

            // Low voltage signal ...
            wire.setVoltage(deviceName, LOW_VOLTAGE);
            sleep(PULSE_WIDTH * 4);

            // Set initial pulse for asynchronous transmission.
            wire.setVoltage(deviceName, HIGH_VOLTAGE);
            sleep(PULSE_WIDTH);

            // Go through bits in the value (big-endian bits first) and send pulses.

            for (int bit = 0; bit < 8; bit++) {
                if ((value & 0x80) == 0x80) {
                    wire.setVoltage(deviceName, HIGH_VOLTAGE);
                } else {
                    wire.setVoltage(deviceName, LOW_VOLTAGE);
                }

                // Shift value.
                value <<= 1;

                sleep(PULSE_WIDTH);
            }
//            wire.setVoltage(deviceName, LOW_VOLTAGE);
        }

    }

    /*
     * Private inner thread class that receives data.
     */
    private class RXThread extends Thread {
        //        private double thresholdVoltage;
        private ArrayList<Integer> receivedPackets = new ArrayList<Integer>();

        public void run() {

            try {

                // Listen for data frames.

                while (true) {

                    byte[] bytePayload = new byte[MAX_PAYLOAD_SIZE];
                    byte[] packet;
                    byte receivedByte;
                    int bytePayloadIndex = 0;
                    int numOfPacketsToSkip = 0;
                    int packetIndex = 0;
                    boolean correctDestination = false;

                    while (true) {

                        receivedByte = receiveByte();

                        if ((receivedByte & 0xFF) == 0x7E) {
                            wire.setVoltage(deviceName, 0.0);
                            break;
                        }

                        // Skip the rest of the bytes if data is not meant for this device.
                        // ===================================================================================
                        if (packetIndex == 0 && receivedByte == deviceNumber) {

                            correctDestination = true;

                        }

                        if (packetIndex == 1 && !correctDestination) {

                            numOfPacketsToSkip = receivedByte;
                            packetIndex++;
                            continue;

                        }

                        if (!correctDestination && (packetIndex < numOfPacketsToSkip)) {

                            packetIndex++;
                            continue;

                        }

                        packetIndex++;

                        System.out.println(deviceName + " RECEIVED BYTE = " + Integer.toHexString(receivedByte & 0xFF));

                        if ((receivedByte & 0xFF) != 0x7E) {
                            // Unstuff if escaped.
                            if (receivedByte == 0x7D) {
                                receivedByte = receiveByte();
                                System.out.println(deviceName + " ESCAPED RECEIVED BYTE = " + Integer.toHexString(receivedByte & 0xFF));
                            }

                            bytePayload[bytePayloadIndex] = receivedByte;
                            bytePayloadIndex++;
                        }

                    }


                    // Create packet, then calculate the checksum.
                    // ================================================================
                    packet = new byte[bytePayloadIndex];

                    for (int i = 0; i < bytePayloadIndex; i++) {
                        packet[i] = bytePayload[i];
                    }

                    // Check if this is ACK confirmatoin.
                    if (packet.length == 3) {

                        // If length of packet is 3, then it is ack.
                        // 0 destination
                        // 1 source
                        // 2 packetId
                        ackReceived = packet;

                        System.out.println("ACK received from: " + packet[1]);
//                        System.out.println("Coming from: " + ackReceived[1]);

                        continue;
                    }


                    if (calculateChecksum(packet) == 0) {
                        System.out.println("CHECKSUM VALID at: " + deviceName);

                        // Include:
                        // 1st byte as destination.
                        // 2nd byte as location.
                        // 3rd byte as packetID.
                        byte[] request = new byte[3];
                        int destination = packet[4];
                        int source = packet[0];
                        int packetId = packet[5];

                        // Send confirmation back to Source.
                        // ====================================================================
                        request[0] = (byte) destination;
                        request[1] = (byte) source;
                        request[2] = (byte) packetId;

                        System.out.println("Adding ACK to queue");
                        outputQueue.put(new DataFrame(request, destination));


                        // Check if we have already received this packet before.
                        if (receivedPackets.indexOf(packet[5]) == -1) {  // First time seeing packet.

                            receivedPackets.add((int) packet[5]);
                            // Block receiving data if queue full.
                            inputQueue.put(new DataFrame(Arrays.copyOfRange(bytePayload, 6, bytePayloadIndex)));

                        } else {                                         // Seen it before.
                            System.out.println("Received a duplicate packet.");
                        }

                    } else {
                        // Your damn data is broken!!!!
                        // A bug in the wire probably corrupted your bytes.
                        System.out.println("CHECKSUM INVALID at netCard: " + deviceNumber);

                        // This could possibly be because there is too much noise.
                        // Try raising the thresholdVoltage.
                        thresholdVoltage += 0.1;
                        System.out.println("Changing threshold at invalid checksum at card: " +
                                "\n " + deviceName + "\n" + thresholdVoltage);

                    }

                }
            } catch (InterruptedException except) {
                System.out.println(deviceName + " Interrupted: " + getName());
            }

        }

        public byte receiveByte() throws InterruptedException {

//            thresholdVoltage = (LOW_VOLTAGE + 2.0 * HIGH_VOLTAGE) / 3.0;
            byte value = 0;

            // Waiting to receive a byte. Will wait until high enough voltage is received before proceeding.
            while (wire.getVoltage(deviceName) < thresholdVoltage) {
                sleep(PULSE_WIDTH / 10);
            }

            // Sleep till middle of next pulse, where bit transmission will begin.
            sleep(PULSE_WIDTH + PULSE_WIDTH / 2);

            value = 0;
            // Use 8 next pulses for byte.
            for (int i = 0; i < 8; i++) {

                value *= 2;

                if (wire.getVoltage(deviceName) > thresholdVoltage) {
                    value += 1;
                }

                sleep(PULSE_WIDTH);
            }

            return value;
        }

    }

    private long calculateChecksum(byte[] packet) {

        byte[] checksum = new byte[2];
        int frameLength = packet.length;
        long checksum16 = 0;
        long data16;
        int packetIndex = 0;

        // Now we need to calculate the 16-bit checksum for frame[].
        while (frameLength > 1) {

            // Create a 16bit integer from 2 values of the data frame.
            data16 = (((packet[packetIndex] << 8) & 0xFF00) | ((packet[packetIndex + 1]) & 0xFF));
            checksum16 += data16;

            // This condition checks if there is any overflow from the 16bits, after addition.
            if ((checksum16 & 0xFFFF0000) > 0) {

                // Removes overflow then carries it over.
                checksum16 = checksum16 & 0xFFFF;
                checksum16 += 1;
            }

            packetIndex += 2;
            frameLength -= 2;
        }

        if (frameLength > 0) {
            checksum16 += ((packet[packetIndex] << 8) & 0xFF00);

            // Once again handle carry bit.
            if ((checksum16 & 0xFFFF0000) > 0) {
                checksum16 = checksum16 & 0xFFFF;
                checksum16 += 1;
            }
        }

        checksum16 = ~checksum16;
        checksum16 = checksum16 & 0xFFFF;

        return checksum16;
        // Now split checksum into 2 bytes;

    }

    private byte[] splitChecksum(long checksum16) {
        byte[] checksum = new byte[2];

        checksum[0] = (byte) ((checksum16 >> 8) & 0x00FF);
        checksum[1] = (byte) (checksum16 & 0x00FF);

        return checksum;
    }

    private DataFrame createPacket(DataFrame frame, int packetId) {
        int destination = frame.getDestination();
        int source = deviceNumber;
        int bytesToIgnore;


        byte[] payload = frame.getTransmittedBytes();
        byte[] payloadWithoutChecksums = new byte[payload.length + 4];
        byte[] payloadWithChecksum = new byte[payload.length + 6];

        bytesToIgnore = 3 + payload.length;

        payloadWithoutChecksums[0] = (byte) destination;
        payloadWithoutChecksums[1] = (byte) bytesToIgnore;
        payloadWithoutChecksums[2] = (byte) source;
        payloadWithoutChecksums[3] = (byte) packetId;

        for (int i = 0; i < payload.length; i++) {
            payloadWithoutChecksums[i + 4] = payload[i];
        }

        // Payload at this stage is missing source, and checksums. Add them in!
        byte[] checksum = splitChecksum(calculateChecksum(payloadWithoutChecksums));

        // Build final packet.
        payloadWithChecksum[0] = (byte) destination;
        payloadWithChecksum[1] = (byte) bytesToIgnore;
        payloadWithChecksum[2] = checksum[0];
        payloadWithChecksum[3] = checksum[1];
        payloadWithChecksum[4] = (byte) source;
        payloadWithChecksum[5] = (byte) packetId;

        for (int i = 0; i < payload.length; i++) {
            payloadWithChecksum[i + 6] = payload[i];
        }

        return new DataFrame(payloadWithChecksum);
    }


}
