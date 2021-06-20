package Patient_Applet;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class Patient_Applet extends Applet {
    
    // CLA: 0x80
    
    // the vital information of the Patient
    final private byte[] pin, hoten, ngaysinh, gioitinh, soBHYT, quequan, mabenhnhan, benhan, avatar, balance;
    private static short len_hoten, len_ngaysinh, len_gioitinh, len_soBHYT, len_quequan, len_mbn, len_benhan, len_avatar, len_balance;
    private static short len_pin, counter;
    
    //  card is block
    private static boolean isBlock_card = false;
    //  send the offset logic
    private final static byte[] logicOffset = {(byte) 0x23, (byte) 0x00, (byte) 0x01};
    
    // temperature data to save data from apdu
    final private byte[] tempBuffer;
    
    // CIPHER, aes, rsa
    final private byte[] rsaPublicKey, rsaPrivateKey, keyRSA;
    private short rsaPublicKeyLen, rsaPrivateKeyLen;
    private Cipher rsaCipher;
     
    final private byte[] aesKey;
    private Cipher aes_ECB_Cipher;
    private byte aesKeyLen;
    private AESKey temp_Aes_Key;
    
    
    // INS case for card
    private static final byte INS_GET_PIN       = (byte) 0x10;
    private static final byte CKECK_CARD_STATUS = (byte) 0x11;
    private static final byte UNBLOCK_CARD      = (byte) 0x12;
    private static final byte RESET_CARD        = (byte) 0x13;
    private static final byte CHECK_PIN         = (byte) 0x14;
    private static final byte CHANGE_PIN        = (byte) 0x15;
    
    // case for patient
    private static final byte INITIALISE_PATIENT    = (byte) 0x20;
    
    private static final byte GET_PATIENT_INFOR     = (byte) 0x21;
    private static final byte UPDATE_PATIENT_INFOR  = (byte) 0x22;
    
    private static final byte GET_PATIENT_SICKNOTE  = (byte) 0x23;
    private static final byte SET_PATIENT_SICKNOTE  = (byte) 0x24;
    
    private static final byte GET_PATIENT_BALANCE   = (byte) 0x25;
    private static final byte SET_PATIENT_BALANCE   = (byte) 0x26;
    

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Patient_Applet();
    }

    protected Patient_Applet() {
        register();
        
        // Patient
        pin         = new byte[18];
        hoten       = new byte[64];
        gioitinh    = new byte[64];
        ngaysinh    = new byte[64];
        quequan     = new byte[64];
        soBHYT      = new byte[64];
        mabenhnhan  = new byte[64];
        benhan      = new byte[64];
        
        avatar      = new byte[64];
        balance     = new byte[64];
        
        
        counter = 3;
        JCSystem.requestObjectDeletion();
        
        tempBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        
        //RSA, AES Cipher
        rsaPublicKey    = new byte[(short) 128];
        rsaPrivateKey   = new byte[(short) 128];
        keyRSA          = new byte[(short) 128];
        rsaPublicKeyLen     = 0;
        rsaPrivateKeyLen    = 0;

        //Create a RSA (with pad) object instance
        rsaCipher       = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        
        //AES   
        aesKey          = new byte[16];
        aesKeyLen       = 0;
        JCSystem.requestObjectDeletion();
        
    }

    public void process(APDU apdu) {
        
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET_PIN:
                get_PIN(apdu);
                break;
            case CKECK_CARD_STATUS:
                check_card_isBlock(apdu);
                break;
            case UNBLOCK_CARD:
                unblock_card(apdu);
                break;
            case RESET_CARD:
                reset_card(apdu);
                break;
            case CHECK_PIN:
                check_PIN_code(apdu, len);
                break;
                
            case INITIALISE_PATIENT:
                initialise_patient(apdu, len);
                break;
            case GET_PATIENT_INFOR:
                get_patient_information(apdu);
                break;
            case UPDATE_PATIENT_INFOR:
                reset_card(apdu);
                initialise_patient(apdu, len);
                break;
                
            case GET_PATIENT_SICKNOTE:
                get_patient_sickNote(apdu);
                break;
            case SET_PATIENT_SICKNOTE:
                set_patient_sickNote(apdu, len);
                break;   
                
            case GET_PATIENT_BALANCE:
                get_patient_balance(apdu);
                break;    
            case SET_PATIENT_BALANCE:
                set_patient_balance(apdu, len);
                break; 
             
            case CHANGE_PIN:
                change_PIN(apdu, len);
                break;
                
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
    
    ///////////FUNCTIONS
    
    // true == block ; false = normal
    private void check_card_isBlock(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 1);
        if (isBlock_card == true) {     //return 1
            apdu.sendBytesLong(logicOffset, (short) 2, (short) 1);
        } else {                        //return 0
            apdu.sendBytesLong(logicOffset, (short) 1, (short) 1);
        }
    }
    
    private void check_PIN_code(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        
        // compare the buffer and PIN code  (equal => 0); (not equal => 1)
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, pin, (short) 0, len) == 0) {
            apdu.sendBytesLong(logicOffset, (short) 1, (short) 1);      //send 0
        } else {
            counter--;
            if (counter == 0) {
                isBlock_card = true;
            }
            apdu.sendBytesLong(logicOffset, (short) 2, (short) 1);      //send 1
        }
    }
    private void get_PIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(pin, (short) 0, buffer, (short) 0, (short) 18);
        apdu.setOutgoingAndSend((short) 0, (short) 18);
    }
    
    private void change_PIN(APDU apdu, short len) {
        len_pin = 18;
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        
        // compare the buffer and PIN code  (equal => 0); (not equal => 1)
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, pin, (short) 0, len) == 0) {
            // same PIN => send 1 => change is not success
            apdu.sendBytesLong(logicOffset, (short) 2, (short) 1);      //send 1
        } else {
            // not same with old PIN => send 0 => change success
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pin, (short)0, (short) 18);
            apdu.sendBytesLong(logicOffset, (short) 1, (short) 1);      //send 0
        }
    }
    
    private void unblock_card(APDU apdu){
        counter = 3;
        isBlock_card = false;
    }

    private void reset_card(APDU apdu) {
        len_gioitinh    = (short) 0;
        len_hoten       = (short) 0;
        len_mbn         = (short) 0;
        len_ngaysinh    = (short) 0;
        len_soBHYT      = (short) 0;
        len_pin         = (short) 0;
        len_quequan     = (short) 0;
        len_benhan      = (short) 0;
        len_balance     = (short) 0;
        Util.arrayFillNonAtomic(hoten,      (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(ngaysinh,   (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(quequan,    (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(mabenhnhan, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(gioitinh,   (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(soBHYT,     (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(pin,        (short) 0, (short) 18, (byte) 0);
        Util.arrayFillNonAtomic(benhan,     (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(balance,     (short) 0, (short) 64, (byte) 0);
        
        Util.arrayFillNonAtomic(rsaPrivateKey,  (short) 0, (short) 128, (byte) 0);
        Util.arrayFillNonAtomic(rsaPublicKey,   (short) 0, (short) 128, (byte) 0);
        Util.arrayFillNonAtomic(aesKey,         (short) 0, (short) 16, (byte) 0);
    }

    private void initialise_patient(APDU apdu, short len) {
        short flag1, flag2, flag3, flag4, flag5, flag6;
        flag1 = flag2 = flag3 = flag4 = flag5 = flag6 = 0; 
        
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)0, len);
        
// data sent from app
//                    String dataArraySender = mabenhnhan.concat("#")
//                        .concat(hoten).concat("#")
//                        .concat(ngaysinh).concat("#")
//                        .concat(gioitinh).concat("#")
//                        .concat(soBHYT).concat("#")
//                        .concat(quequan).concat("#")
//                        .concat(maPIN);

        for(short i = 0; i < len; i++) {
            // check when the position data == "#"
            if(tempBuffer[i] == (byte) 0x23) {
                if(flag1 == 0) {
                    flag1 = i;
                    len_mbn = (short)flag1;
                } else {
                    if(flag2 == 0) {
                        flag2 = i;
                        len_hoten = (short) (flag2 - flag1 - 1);
                    } else {
                        if(flag3 == 0) {
                            flag3 = i;
                            len_ngaysinh = (short) (flag3 - flag2 - 1);
                        } else {
                            if(flag4 == 0) {
                                flag4 = i;
                                len_gioitinh = (short) (flag4 - flag3 - 1);
                            } else {
                                if(flag5 == 0) {
                                    flag5 = i;
                                    len_soBHYT = (short) (flag5 - flag4 - 1);
                                } else {
                                    flag6 = i;
                                    len_quequan = (short) (flag6 - flag5 - 1);
                                    len_pin     = (short) 18;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Util.arrayCopy(tempBuffer, (short)0,           mabenhnhan,  (short)0, len_mbn);    
        Util.arrayCopy(tempBuffer, (short)(flag1 + 1), hoten,       (short)0, len_hoten);
        Util.arrayCopy(tempBuffer, (short)(flag2 + 1), ngaysinh,    (short)0, len_ngaysinh);
        Util.arrayCopy(tempBuffer, (short)(flag3 + 1), gioitinh,    (short)0, len_gioitinh);
        Util.arrayCopy(tempBuffer, (short)(flag4 + 1), soBHYT,      (short)0, len_soBHYT);
        Util.arrayCopy(tempBuffer, (short)(flag5 + 1), quequan,     (short)0, len_quequan);
        Util.arrayCopy(tempBuffer, (short)(flag6 + 1), pin,         (short)0, len_pin);
        
        
        // generate the pair of key before encryption
        gen_RSA_KeyPair(apdu);
        
        // encrypt the private key
        encrypt_private_key(apdu);
        
        // decrypt the private key
        decrypt_private_key(apdu);
        
        // encrypt the patient information
        func_RSA_Cipher_1(apdu, (short) 0, mabenhnhan,  len_mbn,        (short)0);
        func_RSA_Cipher_1(apdu, (short) 0, hoten,       len_hoten,      (short)0);
        func_RSA_Cipher_1(apdu, (short) 0, ngaysinh,    len_ngaysinh,   (short)0);
        func_RSA_Cipher_1(apdu, (short) 0, gioitinh,    len_gioitinh,   (short)0);
        func_RSA_Cipher_1(apdu, (short) 0, soBHYT,      len_soBHYT,     (short)0);
        func_RSA_Cipher_1(apdu, (short) 0, quequan,     len_quequan,    (short)0);
        
        
        // decrypt and send data to apdu with the split symbol == "#" (0x23)
        func_RSA_Cipher_1(apdu, (short) 1, mabenhnhan, len_mbn, (short)0);
        Util.arrayFillNonAtomic(tempBuffer, len_mbn, (short)1, (byte)0x23);     // 0x23 == "#"
        
        func_RSA_Cipher_1(apdu, (short) 1, hoten, len_hoten, (short) (len_mbn + 1));
        Util.arrayFillNonAtomic(tempBuffer, (short) (len_hoten + len_mbn + 1), (short)1, (byte)0x23);     // 0x23 == "#"
        
        func_RSA_Cipher_1(apdu, (short) 1, ngaysinh, len_ngaysinh, (short)(len_hoten + len_mbn + 2));
        Util.arrayFillNonAtomic(tempBuffer, (short) (len_ngaysinh + len_hoten + len_mbn + 2), (short)1, (byte)0x23);
        
        func_RSA_Cipher_1(apdu, (short) 1, gioitinh, len_gioitinh, (short)(len_ngaysinh + len_hoten + len_mbn + 3));
        Util.arrayFillNonAtomic(tempBuffer, (short) (len_gioitinh + len_ngaysinh + len_hoten + len_mbn + 3), (short)1, (byte)0x23);
        
        func_RSA_Cipher_1(apdu, (short) 1, soBHYT, len_soBHYT, (short)(len_gioitinh + len_ngaysinh + len_hoten + len_mbn + 4));
        Util.arrayFillNonAtomic(tempBuffer, (short) (len_soBHYT + len_gioitinh + len_ngaysinh + len_hoten + len_mbn + 4), (short)1, (byte)0x23);
        
        func_RSA_Cipher_1(apdu, (short) 1, quequan, len_quequan, (short)(len_soBHYT + len_gioitinh + len_ngaysinh + len_hoten + len_mbn + 5));
        Util.arrayFillNonAtomic(tempBuffer, (short) (len_quequan + len_soBHYT + len_gioitinh + len_ngaysinh + len_hoten + len_mbn + 5), (short)1, (byte)0x23);
        
        
        // copy data back to buffer and the data with len = 64 bytes after crypting
        Util.arrayCopy(tempBuffer, (short)0, buffer, (short)0, len);
        apdu.setOutgoingAndSend((short)0, len);
    }
    
    private void get_patient_information(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 200);
        buffer[0] = (byte) 0x3a;
        func_AES_Cipher(apdu, rsaPrivateKey, (short) 128, (byte) 1, keyRSA); 

        func_RSA_Cipher_2(apdu, mabenhnhan, (short) 64);
        func_RSA_Cipher_2(apdu, hoten,      (short) 64);
        func_RSA_Cipher_2(apdu, ngaysinh,   (short) 64);
        func_RSA_Cipher_2(apdu, gioitinh,   (short) 64);
        func_RSA_Cipher_2(apdu, soBHYT,     (short) 64);
        func_RSA_Cipher_2(apdu, quequan,    (short) 64);
        
        // get the patient sick note
        get_patient_sickNote(apdu);
        
        // get patient balance
        //get_patient_balance(apdu);
        
    }
    
    // do the sick note
    private void get_patient_sickNote(APDU apdu) {
        if (len_benhan != 0) {
            byte[] buffer = apdu.getBuffer();
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 65);
            func_AES_Cipher(apdu, rsaPrivateKey, (short) 128, (byte) 1, keyRSA);
            func_RSA_Cipher_2(apdu, benhan, (short) 64);
        }
    }
    private void set_patient_sickNote(APDU apdu, short len) {
        len_benhan = (short) len;
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 65);
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, benhan, (short) 0, len);
        func_RSA_Cipher_1(apdu, (short) 0, benhan, len_benhan, (short) 0);
        func_RSA_Cipher_2(apdu, benhan, (short) 64);
    }
    
    // do the balance.
    private void get_patient_balance(APDU apdu) {
        if (len_balance != 0) {
            byte[] buffer = apdu.getBuffer();
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 65);
            func_AES_Cipher(apdu, rsaPrivateKey, (short) 128, (byte) 1, keyRSA);
            func_RSA_Cipher_2(apdu, balance, (short) 64);
        }
    }
    private void set_patient_balance(APDU apdu, short len) {
        len_balance = (short) len;
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 65);
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, balance, (short) 0, len);
        func_RSA_Cipher_1(apdu, (short) 0, balance, len_balance, (short) 0);
        func_RSA_Cipher_2(apdu, balance, (short) 64);
    }
    
    
    
    // ENCRYPTION - DECRYPTION PART
    
    private void encrypt_private_key(APDU apdu) {
        set_AES_Key(apdu, len_pin);
        func_AES_Cipher(apdu, rsaPrivateKey, (short) 128, (byte) 0, rsaPrivateKey);
    }

    private void decrypt_private_key(APDU apdu) {
        set_AES_Key(apdu, len_pin);//ok
        func_AES_Cipher(apdu, rsaPrivateKey, (short) 128, (byte) 1, keyRSA);
    }
    
    // RSA algorithm encrypt and decrypt, 
    // default P2=00, P1 optional
    //  mode: encrypt or decrypt mode
    private void func_RSA_Cipher_1(APDU apdu, short mode, byte[] arr, short len, short off) {
        byte[] buffer = apdu.getBuffer();
        short keyLen = KeyBuilder.LENGTH_RSA_512;
        short offset = (short) 64;
        
        if (len <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        // RSA encryption with the Public Key is used
        if(mode == (short) 0) {
            // public key
            RSAPublicKey pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keyLen, false); // encryptKey = false
            pubKey.setModulus(rsaPublicKey, (short) 0, offset);
            pubKey.setExponent(rsaPublicKey, offset, (short) 3);
            
            // In multiple-part encryption/decryption operations, only the fist APDU command will be used.
            rsaCipher.init(pubKey, Cipher.MODE_ENCRYPT);
            
            // output with the input encryption
            // (array_input, offset_in, len, array_out, offset_out)
            short outputLen = rsaCipher.doFinal(arr, (short) 0, len, buffer, (short) 0);
            
            // apdu.setOutgoingAndSend((short) 0, outputLen);
            
            //  save back to buffer after encrypting
            Util.arrayCopy(buffer, (short) 0, arr, (short) 0, outputLen);
            
        } else {    // RSA decryption, using private key
            RSAPrivateKey priKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLen, false);
            priKey.setModulus(keyRSA, (short) 0, offset);
            priKey.setExponent(keyRSA, offset, offset);
        
            rsaCipher.init(priKey, Cipher.MODE_DECRYPT);
            short outputLen = rsaCipher.doFinal(arr, (short) 0, (short) 64, tempBuffer, off);
            
            //apdu.setOutgoingAndSend((short) 0, outputLen);        
        } 
    }
    
    private void func_RSA_Cipher_2(APDU apdu, byte[] arr, short len) {
        byte[] buffer = apdu.getBuffer();
        short keyLen = KeyBuilder.LENGTH_RSA_512;
        short offset = (short) 64;
        RSAPrivateKey priKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLen, false);
        priKey.setModulus(keyRSA, (short) 0, offset);
        priKey.setExponent(keyRSA, offset, offset);
        
        rsaCipher.init(priKey, Cipher.MODE_DECRYPT);
        short outlen = rsaCipher.doFinal(arr, (short) 0, len, buffer, (short) 0);
        apdu.sendBytes((short) 0, outlen);
        apdu.sendBytesLong(logicOffset, (short) 0, (short) 1);
    }
    
    
    // Get the value of RSA Public Key from the global variable 'rsaPubKey'
    // P1=0 => get the modulus N; P1=1 => get the Exponent E
    private void get_RSA_PublicKey(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        if (rsaPublicKeyLen == 0) {
            ISOException.throwIt((short) 0x6A88);
        }
        short modLen = (short) 64;
        switch (buffer[ISO7816.OFFSET_P1]) {
            case 0:
                //get puclic key N
                Util.arrayCopyNonAtomic(rsaPublicKey, (short) 0, buffer, (short) 0, modLen);
                apdu.setOutgoingAndSend((short) 0, modLen);
                break;
            case 1:
                //get public key E
                short eLen = (short) (rsaPublicKeyLen - modLen);
                Util.arrayCopyNonAtomic(rsaPublicKey, modLen, buffer, (short) 0, eLen);
                apdu.setOutgoingAndSend((short) 0, eLen);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
    }
    
    //  get RSA private key
    //  mode is get the N(0) or D(1)
    private void get_RSA_PrivateKey(byte[] arr, byte mode) {
        //byte[] buffer = apdu.getBuffer();
        short ret = get_RSA_PrivateKeyComponent(mode, arr, (short) 0);//mode, outbuf, offbuf
        if (ret == 0) {
            ISOException.throwIt((short) 0x6A88);
        }
        //apdu.setOutgoingAndSend((short) 0, ret);
    }
    
    //According to the different ID, returns the value/length of RSA Private key component
    // P1 == id
    private short get_RSA_PrivateKeyComponent(byte id, byte[] outBuffer, short outOffset) {
        if(rsaPrivateKeyLen == 0) {
            return (short) 0;
        }
        short modLen = (short) 64;              // length of the module N of the key
        short readOffset;                       // read from where (position)
        short readLen;                          // read how many (bytes)
        
        switch(id) {
            case (byte) 0:
                // RSA private key with N
                readOffset = (short) 0;
                readLen = modLen;
                break;
            case (byte) 1:
                // RSA private key with D
                readOffset = modLen;
                readLen = modLen;
                break;
            default:
                return 0;
        }
        
        Util.arrayCopyNonAtomic(rsaPrivateKey, readOffset, outBuffer, outOffset, readLen);
        return readLen;
    }
    
    private void gen_RSA_KeyPair(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        try {
            KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
            keyPair.genKeyPair();
            
            JCSystem.beginTransaction();
            rsaPublicKeyLen = 0;
            rsaPrivateKeyLen = 0;
            JCSystem.commitTransaction();
            
            //Get a reference to the public key component of this 'keyPair' object.
            RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
            
            short pubKeyLen = 0;
            //Store the RSA public key value in the global variable 'rsaPublicKey', the public key contains modulo N and Exponent E
            pubKeyLen += pubKey.getModulus(rsaPublicKey, pubKeyLen);            // modulo N
            pubKeyLen += pubKey.getExponent(rsaPublicKey, pubKeyLen);           // Exponent E
            
            
            //Returns a reference to the private key component of this KeyPair object.
            RSAPrivateKey priKey = (RSAPrivateKey) keyPair.getPrivate();
            
            short priKeyLen = 0;
            //RSA Algorithm,  the Private Key contains N and D, and store these parameters value in global variable 'rsaPriKey'.
            priKeyLen += priKey.getModulus(rsaPrivateKey, priKeyLen);           //N
            priKeyLen += priKey.getExponent(rsaPrivateKey, priKeyLen);          //D
                
            
            JCSystem.beginTransaction();
            rsaPublicKeyLen = pubKeyLen;
            rsaPrivateKeyLen = priKeyLen;
            JCSystem.commitTransaction();
                
        } catch(CryptoException err) {
            short error_reason = err.getReason();
            ISOException.throwIt(error_reason);
        }
    
        JCSystem.requestObjectDeletion();
    }
    
    //set AES key 128bit (16 byte)
    private void set_AES_Key(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        byte keyLen = 16;               // The length of key is 16 bytes
        if (len < 16)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        //Copy the incoming AES Key value to the variable 'aesKey'
        JCSystem.beginTransaction();
        Util.arrayCopy(pin, (short) 0, aesKey, (short) 0, (short) 16);
        aesKeyLen = keyLen;
        JCSystem.commitTransaction();
    }
    
    //AES algorithm encrypt and decrypt, p1==00 encrypt else decrypt, p2=00    (cipher mode block)ecb
    private void func_AES_Cipher(APDU apdu, byte[] arr, short len, byte mod, byte[] arr_byte) {
        try {
            byte[] buffer = apdu.getBuffer();
            aes_ECB_Cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);       //externalAccess=false
            temp_Aes_Key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            if (len <= 0 || len % 16 != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            temp_Aes_Key.setKey(aesKey, (short) 0);
            byte mode = mod == (byte) 0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
            Cipher cipher = aes_ECB_Cipher;
            cipher.init(temp_Aes_Key, mode);

            if (mode == 0) {
                cipher.doFinal(arr, (short) 0, len, buffer, (short) 0);
                Util.arrayCopy(buffer, (short) 0, arr, (short) 0, len);
            } else {
                cipher.doFinal(arr, (short) 0, len, buffer, (short) 0);
                Util.arrayCopy(buffer, (short) 0, arr_byte, (short) 0, len);
            }
        } catch (CryptoException e) {
            short reason = e.getReason();
            ISOException.throwIt(reason);
        }
    }
    

}
