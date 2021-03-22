# Hướng giải một số thử thách Cryptography KCSC CTF 2021.
## Crypto 1
Cho biết `FLAG` bắt đầu bằng 4 byte `KCSC`, một S-box 256 phần tử đóng vai trò là phép thế. Khóa có độ dài là 1 byte (vì mod 256 nên khóa thuộc đoạn [0, 255]).

FLAG sẽ được biến đổi qua 256 vòng lặp, mỗi vòng thực hiện cập nhật khóa, XOR bản rõ với khóa và phép thay thế với S-box.

Các biến đổi trên FLAG hoàn toàn có thể đảo ngược lại.

**Gợi ý:** tạo một S-box<sup>-1</sup> ngược với S-box ban đầu, quét cạn khóa từ 0 đến 255, mỗi vòng lặp làm ngược lại với lúc mã hóa (S-box<sup>-1</sup>, XOR, cập nhật khóa).


## Crypto 2
Cho một RSA server thực hiện giải mã bản các mã nhận được, trả về một bit ở vị trí x của bản rõ (thứ tự tính từ 0, từ trái sang phải).
Cho biết n là tích của 2 số nguyên tố 1024 bit, e, `encrypted_flag`, độ dài của FLAG là 37 byte và x (x thuộc [8*len(FLAG), 1024] = [296,1024]). Đảm bảo khi gửi `encrypted_flag` server luôn trả về 0.

**Gợi ý:** Độ dài của n là 2048 bit, lớn hơn nhiều độ dài của FLAG (296 bit), khôi phục FLAG bằng cách nhân bản mã `encrypted_flag` với (2<sup>i</sup>)<sup>65537</sup> sao cho bit cần tìm nằm ở vị trí x.


## Crypto 3
Một server yêu cầu 2 mật khẩu khác nhau, sử dụng PBKDF2 để tạo khóa cho từng mật khẩu. Yêu cầu hai khóa phải giống nhau, 4 byte `KCSC` thuộc mật khẩu 1 thì server sẽ trả về một đoạn của FLAG.
**Gợi ý:** [HMAC collisions](https://en.wikipedia.org/wiki/PBKDF2#HMAC_collisions), để trả về toàn bộ FLAG thì mật khẩu 2 phải bắt đầu bằng 2 byte 0000H.


## Crypto-4
Một server dùng thuật toán chữ ký số trên đường cong Elliptic P-256 để ký `KCSC`. Server cho phép 2 lựa chọn là `flip` 1 bit ở `index` của `private_key` và trả về chữ ký bị lỗi, `guess` `private_key`, nếu đúng sẽ trả về FLAG.

**Gợi ý**: [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm).
Khi lật một bit ở thứ tự i (đếm từ 0), thu được:
\^{s}
