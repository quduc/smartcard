
package smartcard_building;

/**
 *
 * @author Dang Nam
 */
public class Patient {
    private String hoten;
    private String ngaysinh;
    private String quequan;
    private String maBenhNhan;
    private String gioitinh;
    private String soBHYT;
    private String benhan;
    private String maPIN;
    private int soDu;

    public void setHoten(String hoten) {
        this.hoten = hoten;
    }

    public void setNgaysinh(String ngaysinh) {
        this.ngaysinh = ngaysinh;
    }

    public void setQuequan(String quequan) {
        this.quequan = quequan;
    }

    public void setMaBenhNhan(String maBenhNhan) {
        this.maBenhNhan = maBenhNhan;
    }

    public void setGioitinh(String gioitinh) {
        this.gioitinh = gioitinh;
    }

    public void setSoBHYT(String soBHYT) {
        this.soBHYT = soBHYT;
    }
    
    public void setBenhAn(String benhan) {
        this.benhan = benhan;
    }

    public void setMaPIN(String maPIN) {
        this.maPIN = maPIN;
    }

    public void setSoDu(int soDu) {
        this.soDu = soDu;
    }

    public String getHoten() {
        return hoten;
    }

    public String getNgaysinh() {
        return ngaysinh;
    }

    public String getQuequan() {
        return quequan;
    }

    public String getMaBenhNhan() {
        return maBenhNhan;
    }

    public String getGioitinh() {
        return gioitinh;
    }
    
    public String getSoBHYT() {
        return soBHYT;
    }

    public String getBenhan() {
        return benhan;
    }

    public String getMaPIN() {
        return maPIN;
    }

    public int getSoDu() {
        return soDu;
    }
    
    
    
    public Patient(String hoten, String ngaysinh, String quequan, String maBenhNhan, String gioitinh, String soBHYT, String maPIN, int soDu) {
        this.hoten = hoten;
        this.ngaysinh = ngaysinh;
        this.quequan = quequan;
        this.maBenhNhan = maBenhNhan;
        this.gioitinh = gioitinh;
        this.soBHYT = soBHYT;
        this.maPIN = maPIN;
        this.soDu = soDu;
    }
    
    public Patient() {}
    
}
