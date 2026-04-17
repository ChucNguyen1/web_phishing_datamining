# Giai thich ngu nghia bo du lieu Phishing Websites

## 1) Tong quan bo du lieu

Bo du lieu nay mo ta cac dac trung cua website de phan loai website la **phishing** hay **hop le (legitimate)**.

- Tong so thuoc tinh dau vao: **30**
- Cot nhan (label): **Result**
- Tong so cot moi dong: **31** (30 dac trung + 1 nhan)

So mau trong workspace:

- `Training Dataset.arff`: **11055** mau
  - Result = 1: 6157
  - Result = -1: 4898
- `.old.arff`: **2456** mau
  - Result = 1: 1094
  - Result = -1: 1362

## 2) Nhom y nghia cac thuoc tinh

### A. Dac trung URL va ten mien

- `having_IP_Address`: URL co dung dia chi IP thay vi domain hay khong.
- `URL_Length`: do dai URL (ngan/vua/dai).
- `Shortining_Service`: co dung dich vu rut gon URL hay khong.
- `having_At_Symbol`: URL co ky tu `@` hay khong.
- `double_slash_redirecting`: co dau hieu redirect bat thuong bang `//` trong URL.
- `Prefix_Suffix`: domain co dau `-` (dang thuong gap trong phishing).
- `having_Sub_Domain`: muc do su dung subdomain (qua nhieu subdomain thuong rui ro hon).
- `HTTPS_token`: domain co chua chuoi `https` sai ngu canh hay khong (de danh lua nguoi dung).

### B. Dac trung SSL, dang ky, DNS, tuoi mien

- `SSLfinal_State`: chat luong/trang thai SSL chung chi.
- `Domain_registeration_length`: thoi han dang ky domain (ngan thuong rui ro hon).
- `age_of_domain`: tuoi cua domain.
- `DNSRecord`: co ton tai/thong tin DNS hop le hay khong.

### C. Dac trung noi dung trang va hanh vi HTML/JS

- `Favicon`: favicon co den tu nguon dang ngo hay khong.
- `port`: su dung cong mang bat thuong.
- `Request_URL`: ty le tai nguyen (anh, script, media...) tai tu domain ngoai.
- `URL_of_Anchor`: cac the anchor (`<a>`) co lien ket bat thuong.
- `Links_in_tags`: lien ket trong cac the metadata/script/link co bat thuong hay khong.
- `SFH`: Server Form Handler (hanh vi form submission an toan hay nguy hiem).
- `Submitting_to_email`: form gui du lieu truc tiep qua email.
- `Abnormal_URL`: URL bat thuong so voi ten mien va cau truc thong thuong.
- `Redirect`: so lan/chieu huong redirect.
- `on_mouseover`: co script thay doi thanh trang thai khi re chuot.
- `RightClick`: vo hieu hoa chuot phai.
- `popUpWidnow`: su dung pop-up bat thuong.
- `Iframe`: su dung iframe an/nhung noi dung dang ngo.

### D. Dac trung danh tieng va muc do pho bien

- `web_traffic`: luong truy cap website.
- `Page_Rank`: do uy tin/thu hang trang.
- `Google_Index`: website co duoc Google index hay khong.
- `Links_pointing_to_page`: so lien ket tro den trang.
- `Statistical_report`: co bi danh dau trong cac bao cao thong ke/blacklist hay khong.

## 3) Ngu nghia gia tri ma hoa

Bo du lieu su dung ma so roi rac (`-1`, `0`, `1`) de bieu dien muc do rui ro.

- Thuong gap:
  - `-1`: nghi ngo/phishing
  - `0`: trung tinh/khong ro
  - `1`: hop le/an toan
- Tuy nhien, mot so file co the dao nguoc ma hoa o mot so thuoc tinh. Vi vay can doc theo schema tung file.

## 4) Khac biet giua 2 file trong workspace

Hai file co cung ten thuoc tinh va cung thu tu cot, nhung khac nhau ve **mien gia tri (encoding)**:

- `Training Dataset.arff`:
  - Nhieu cot nhi phan dung `{ -1, 1 }`
  - Mot so cot 3 muc `{ -1, 0, 1 }`
- `.old.arff`:
  - Nhieu cot nhi phan dung `{ 0, 1 }`
  - Mot so cot 3 muc van dung `{ -1, 0, 1 }`

Vi du ro nhat:

- `having_IP_Address`: training `{ -1,1 }`, old `{ 1,0 }`
- `Favicon`: training `{ 1,-1 }`, old `{ 0,1 }`
- `Result`: training `{ -1,1 }`, old `{ 1,-1 }`

### Dien giai thuc te khi dung chung 2 file

Khi ket hop/so sanh 2 file, ban nen chuan hoa ma hoa ve cung mot chuan (khuyen nghi `-1/0/1`).
Neu khong, model co the hieu sai ngu nghia (vi cung so `1` nhung y nghia co the khac file).

## 5) Y nghia nhan `Result`

Theo quy uoc pho bien cua bo du lieu phishing websites:

- `Result = -1`: phishing
- `Result = 1`: legitimate

Luu y: do `.old.arff` su dung encoding cu, can kiem tra pipeline tien xu ly de tranh dao nhan ngoai y muon khi huan luyen.

## 6) Goi y tien xu ly cho mo hinh

- Doc schema rieng cho tung file truoc khi gop du lieu.
- Chuan hoa ma hoa tat ca cot ve cung quy uoc.
- Kiem tra can bang nhan sau khi gop.
- Luu bang mapping (old -> standardized) de tai lap ket qua.

---

Neu ban muon, toi co the viet tiep mot file mapping cu the tung cot (vi du: voi moi cot trong `.old.arff`, gia tri `0/1` se doi thanh gi trong chuan `-1/0/1`) de ban dung truc tiep trong Python/Weka.
