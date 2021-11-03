import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class E2EEChat
{
    // 키, iv를 저장하기위함
    String aesKey = null;
    String iv = null;
    PublicKey publicKey = null; //나의 공개키
    PrivateKey privateKey = null; //나의 비밀키
    PublicKey peersPublickey = null; //상대방의 공개키
    boolean havePeerKey = false; // 상대방의 공개키를 가지고있는지 flag
    //

    private Socket clientSocket = null;

    public Socket getSocketContext() {
        return clientSocket;
    }

    // 접속 정보, 필요시 수정
    private final String hostname = "homework.islab.work";
    private final int port = 8080;

    public E2EEChat() throws IOException, NoSuchAlgorithmException {
        //나의 RSA 키 쌍 생성
        RSAUtil rsaUtil = new RSAUtil();
        KeyPair keyPair = rsaUtil.genRSAKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        //
       clientSocket = new Socket();
       clientSocket.connect(new InetSocketAddress(hostname, port));

       InputStream stream = clientSocket.getInputStream();

       Thread senderThread = new Thread(new MessageSender(this));
       senderThread.start();

       while (true) {
           try {
               if (clientSocket.isClosed() || !senderThread.isAlive()) {
                   break;
               }

               byte[] recvBytes = new byte[2048];
               int recvSize = stream.read(recvBytes);

               if (recvSize == 0) {
                   continue;
               }

               String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

               parseReceiveData(recv);
           } catch (IOException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
               System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
               break;
           }
       }

       try {
           System.out.println("입력 스레드가 종료될때까지 대기중...");
           senderThread.join();

           if (clientSocket.isConnected()) {
               clientSocket.close();
           }
       } catch (InterruptedException ex) {
           System.out.println("종료되었습니다.");
       }
    }

    public void parseReceiveData(String recvData) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException, InvalidKeyException {
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.

        //구현부분
        String[] message = recvData.split("\n");
        String[] firstLine = message[0].trim().split(" ");
        String method = firstLine[1].trim();
        String decrypted = "";

        int bodyIndex = 0;
        for(int i = 0; i < message.length; i++){
            if (message[i].equals("")) {
                bodyIndex = i+1;
            }
        }

        if (method.equalsIgnoreCase("KEYXCHG") || method.equalsIgnoreCase("KEYXCHGRST")) {
            if(havePeerKey){ //서로의 공개키교환이 완료되었을때
                RSAUtil rsaUtil = new RSAUtil();
                this.aesKey = rsaUtil.decryptRSA(message[bodyIndex], this.privateKey);
                this.iv = rsaUtil.decryptRSA(message[bodyIndex+1], this.privateKey);
                message[bodyIndex] = this.aesKey;
                message[bodyIndex+1] = this.iv;
            } else {
                this.aesKey = message[bodyIndex];
                this.iv = message[bodyIndex+1];
            }
        } else if (method.equalsIgnoreCase("MSGRECV")) {
            if(message[bodyIndex].equalsIgnoreCase("RSA")) { //body의 첫째줄에 RSA가 적혀있을경우
                RSAUtil rsaUtil = new RSAUtil();
                this.peersPublickey = rsaUtil.getPublicKeyFromBase64String(message[bodyIndex+1]); //상대의 공개키획득
                this.havePeerKey = true; //상대의 공개키를 가지고있다는 flag를 true로
            } else {
                decrypted = new AES256().decrypt(this.aesKey, this.iv, message[bodyIndex]);
            }
        }

        recvData = "";
        for (int i = 0; i < message.length-1; i++){
            recvData += (message[i] + "\n");
        }
        if(decrypted.equals("")){
            recvData += message[message.length-1];
        } else {
            recvData += decrypted;
        }
        recvData = recvData.trim();
        //

        System.out.println(recvData + "\n==== recv ====");

    }

    // 필요한 경우 추가로 메서드를 정의하여 사용합니다.

    public static void main(String[] args)
    {
        try {
            new E2EEChat();
        } catch (UnknownHostException ex) {
            System.out.println("연결 실패, 호스트 정보를 확인하세요.");
        } catch (IOException ex) {
            System.out.println("소켓 통신 중 문제가 발생하였습니다.");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class MessageSender implements Runnable {
    E2EEChat clientContext;
    OutputStream socketOutputStream;

    public MessageSender(E2EEChat context) throws IOException {
        clientContext = context;

        Socket clientSocket = clientContext.getSocketContext();
        socketOutputStream = clientSocket.getOutputStream();
    }

    @Override
    public void run() {
        //Scanner scanner = new Scanner(System.in);
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            try {
                System.out.print("MESSAGE: ");

                //추가된 부분(보낼 때) *보낼때 줄바꿈 후 send를 입력해야지만 보내지도록 구현하였습니다
                String message = "";
                String line;

                while ((line = br.readLine()) != null) {
                    if (line.equalsIgnoreCase("Send")) { //마지막에 Send를 입력해야 보내지도록
                        message = message.trim(); //마지막 개행문자 제거
                        break;
                    }
                    message += (line + "\n");
                }

                String[] forCheck = message.split("\n"); //메시지 검사를 위한 문자열배열

                String[] firstLine = forCheck[0].trim().split(" "); //3EPROTO와 METHOD
                String method = firstLine[1].trim();

                int bodyIndex = 0; //body의 index를 저장하기위한 변수
                for(int i = 0; i < forCheck.length; i++){
                    if(forCheck[i].equals("")) { //공백라인 이후로 body
                        bodyIndex = i+1;
                    }
                }

                if(method.equalsIgnoreCase("KEYXCHG") || method.equalsIgnoreCase("KEYXCHGRST")) { //키교환이나 키변경의 경우
                    clientContext.aesKey = forCheck[bodyIndex];
                    clientContext.iv = forCheck[bodyIndex+1];
                    if(clientContext.havePeerKey){
                        RSAUtil rsaUtil = new RSAUtil();
                        forCheck[bodyIndex] = rsaUtil.encryptRSA(forCheck[bodyIndex], clientContext.peersPublickey);
                        forCheck[bodyIndex+1] = rsaUtil.encryptRSA(forCheck[bodyIndex+1], clientContext.peersPublickey);
                    }
                } else if(method.equalsIgnoreCase("MSGSEND")) { //메세지 송신의 경우
                    if(forCheck[bodyIndex].equalsIgnoreCase("RSA")){ //body에 RSA와 다음줄에 publickey를 작성해야됨 (공개키전송)
                        byte[] bytePublicKey = clientContext.publicKey.getEncoded();
                        String base64PublicKey = Base64.getEncoder().encodeToString(bytePublicKey);
                        forCheck[bodyIndex+1] = base64PublicKey;    
                    } else {
                        String encrypted = new AES256().encrypt(clientContext.aesKey, clientContext.iv, forCheck[bodyIndex]);
                        forCheck[bodyIndex] = encrypted;
                    }
                }

                message = ""; //암호화한 평문으로 수정하기위함
                for (int i = 0; i < forCheck.length; i++){
                    message += (forCheck[i] + "\n");
                }
                message = message.trim(); //마지막 개행문자 제거
                //

                //String message = scanner.nextLine().trim();
                byte[] payload = message.getBytes(StandardCharsets.UTF_8);

                socketOutputStream.write(payload, 0, payload.length);
            } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                break;
            }
        }

        System.out.println("MessageSender runnable end");
    }
}

class AES256 { //AES256CBC 클래스 정의

    public String encrypt(String key, String iv, String data){
        try {
            key = key.substring(0, 32);
            byte[] keyByte = key.getBytes(StandardCharsets.UTF_8);
            iv = iv.substring(0, 16);
            byte[] ivByte = iv.getBytes(StandardCharsets.UTF_8);
            SecretKey secretKey = new SecretKeySpec(keyByte, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //자바에서는 PKCS7이 없고 PKCS5가 PKCS7으로 수행된다고함
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(ivByte));

            byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return new String(Base64.getEncoder().encode(encrypted));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return "error";
    }

    public String decrypt(String key, String iv, String encryptData){
        try {
            key = key.substring(0, 32);
            byte[] keyByte = key.getBytes(StandardCharsets.UTF_8);
            iv = iv.substring(0, 16);
            byte[] ivByte = iv.getBytes(StandardCharsets.UTF_8);
            SecretKey secretKey = new SecretKeySpec(keyByte, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //자바에서는 PKCS7이 없고 PKCS5가 PKCS7으로 수행된다고함
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivByte));

            byte[] decrypted = Base64.getDecoder().decode(encryptData.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(decrypted), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return "error";
    }

}

class RSAUtil {

    public KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024, secureRandom); //1024비트 RSA 키 쌍 생성
        KeyPair keyPair = gen.genKeyPair();
        return keyPair;
    }

    public String encryptRSA(String data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] byteData = cipher.doFinal(data.getBytes());
        String encrypted = Base64.getEncoder().encodeToString(byteData);
        return encrypted;
    }

    public String decryptRSA(String data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("RSA");
        byte[] byteData = Base64.getDecoder().decode(data.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] byteDecrypted = cipher.doFinal(byteData);
        String decrypted = new String(byteDecrypted, "utf-8");
        return decrypted;
    }

    public PrivateKey getPrivateKeyFromBase64String(final String keyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String privateKeyString = keyString.replaceAll("\\n", "").replaceAll("-{5}[ a-zA-Z]*-{5}", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
        return keyFactory.generatePrivate(keySpecPKCS8);
    }

    public PublicKey getPublicKeyFromBase64String(final String keyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String publicKeyString = keyString.replaceAll("\\n", "").replaceAll("-{5}[ a-zA-Z]*-{5}", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
        return keyFactory.generatePublic(keySpecX509);
    }

}