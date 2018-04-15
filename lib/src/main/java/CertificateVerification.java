import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by Nightzsky on 4/2/2018.
 */

public class CertificateVerification {
    public static void main(String[] args){
        try {
            InputStream fis = new FileInputStream("C:\\Users\\Nightzsky\\Downloads\\CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate)cf.generateCertificate(fis);
            PublicKey CAkey = CAcert.getPublicKey();

            InputStream server = new FileInputStream("C:\\Users\\Nightzsky\\Downloads\\server.crt");
            CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
            X509Certificate ServerCert = (X509Certificate) cf2.generateCertificate(server);

            ServerCert.checkValidity();
            ServerCert.verify(CAkey);
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }

}
