package smartcard_building;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import com.sun.javacard.apduio.*;

public class SmartCard_Building {
    
    private Apdu apdu;
    private Socket sock;
    private OutputStream os;
    private InputStream is;
    private CadClientInterface cad;
    
    public SmartCard_Building() {
        apdu = new Apdu();
    }
    
    // connect to applet with port 9025
    public void establishConnectionToSimulator() {
        try {
            sock = new Socket("localhost", 9025);
            os = sock.getOutputStream();
            is = sock.getInputStream();
            
            // init a entity applet through java card runtime using port 9025
            cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);            
        } catch(IOException err) {
            err.printStackTrace();
        }
    }
    
    // close the connection with JCR
    public void closeConnection() {
        try {
            sock.close();
        } catch(IOException err) {
            err.printStackTrace();
        }
    }
    
    // provided the power for cad
    public void pwrUp() {
        try {
            if(cad != null) {
                cad.powerUp();
            }
        } catch(IOException | CadTransportException e) {
            e.printStackTrace();
        }
    }
    
    // cute the power of cad
    public void pwrDown() {
        try {
            if(cad != null) {
                cad.powerDown(true);
            }
            if(sock != null) {
                sock.close();
            }
        } catch(IOException | CadTransportException e) {
            e.printStackTrace();
        }
    }
    
    //set APDU cmd (HEADER)
    public void setTheAPDUCommands(byte[] commands) {
        if (commands.length > 4 || commands.length == 0) {
            System.err.println("inavlid commands");
        } else {
            apdu.command = commands;
            System.out.println("CLA: " + atrToHex(commands[0]));
            System.out.println("INS: " + atrToHex(commands[1]));
            System.out.println("P1: " + atrToHex(commands[2]));
            System.out.println("P2: " + atrToHex(commands[3]));
        }
    }
    
    // set LC
    public void setTheDataLength(byte len) {
        apdu.Lc = len;
        System.out.println("Lc: " + atrToHex(len));
    }
    public void setTheDataLengthShort(short len) {
        apdu.Lc = len;
        System.out.println("Lc: " + shorttoHex(len));
    }
    
    // set Le
    public void setExpectedByteLength(byte len) {
        apdu.Le = len;
        System.out.println("Le: " + atrToHex(len));
    }
    public void setExpectedShortLength(short len) {
        apdu.Le = len;
        System.out.println("Le: " + shorttoHex(len));
    }
    //get sw1 sw2, convert to hex
    public byte[] decodeStatus() {
        byte[] statByte = apdu.getSw1Sw2();
        System.out.println("SW1: " + atrToHex(statByte[0]));
        System.out.println("SW2: " + atrToHex(statByte[1]));
        return statByte;
    }

    
    
    
    // send data to applet (byte[] data)
    public void setTheDataIn(byte[] data) {
        if(data.length != apdu.Lc) {
            System.err.println("The number of data in the array are more than expected");
        } else {
            //set the data to be sent to the applets
            apdu.dataIn = data;
            for (int i = 0; i < data.length; i++) {
                System.out.println("dataIndex" + i + ": " + atrToHex(data[i]));
            }
        }
    }
    
    // exchange data from applet (apdu receive data from applet)
    public void exchangeTheAPDUWithSimulator() {
        try {
            apdu.setDataIn(apdu.dataIn, apdu.Lc);
            //start exchange data throught apdu with applet
            cad.exchangeApdu(apdu);
        } catch (IOException | CadTransportException e) {
            e.printStackTrace();
        }
    }
    

    //convert data respone to hex
    public byte[] decodeDataOut() {
        byte[] dout = apdu.dataOut;
        for (int i = 0; i < dout.length; i++) {
            System.out.println("dataOut" + i + ": " + atrToHex(dout[i]));
        }
        return dout;
    }
    //convert byte to hex
    public String atrToHex(byte atCode) {
        StringBuilder result = new StringBuilder();
            result.append(String.format("%02x", atCode));
        return result.toString();
    }
    public String shorttoHex(short atCode) {
        StringBuilder result = new StringBuilder();
            result.append(String.format("%02x", atCode));
        return result.toString();
    }
    
    
    /**
     * @param args the command line arguments
     
    public static void main(String[] args) {
        // TODO code application logic here
    }
    
    * */
}
