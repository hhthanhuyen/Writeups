# Hướng giải một số thử thách Cryptography KCSC CTF 2021.
## Crypto 1 - Reverse
Cho biết `FLAG` bắt đầu bằng 4 byte `KCSC`, một S-box 256 phần tử đóng vai trò là phép thế. Khóa có độ dài là 1 byte (vì mod 256 nên khóa thuộc đoạn [0, 255]).
FLAG sẽ được biến đổi qua 256 vòng lặp, mỗi vòng thực hiện cập nhật khóa, XOR bản rõ với khóa và phép thay thế với S-box.
Các biến đổi trên FLAG hoàn toàn có thể đảo ngược lại.

**Gợi ý:** tạo một S-box<sup>-1</sup> ngược với S-box ban đầu, quét cạn khóa từ 0 đến 255, mỗi vòng lặp làm ngược lại với lúc mã hóa (S-box<sup>-1</sup>, XOR, cập nhật khóa).


## Crypto 2 - Alter The Future
Cho một RSA server thực hiện giải mã bản các mã nhận được, trả về một bit ở vị trí x của bản rõ (thứ tự tính từ 0, từ trái sang phải).
Cho biết n là tích của 2 số nguyên tố 1024 bit, e, `encrypted_flag`, độ dài của FLAG là 37 byte và x (x thuộc [8*len(FLAG), 1024] = [296,1024]). Đảm bảo khi gửi `encrypted_flag` server luôn trả về 0.

**Gợi ý:** Độ dài của n là 2048 bit, lớn hơn nhiều độ dài của FLAG (296 bit), khôi phục FLAG bằng cách nhân bản mã `encrypted_flag` với (2<sup>i</sup>)<sup>65537</sup> sao cho bit cần tìm nằm ở vị trí x.


## Crypto 3 - Double Slap
Một server yêu cầu 2 mật khẩu khác nhau, sử dụng PBKDF2 để tạo khóa cho từng mật khẩu. Yêu cầu hai khóa phải giống nhau, 4 byte `KCSC` thuộc mật khẩu 1 thì server sẽ trả về một đoạn của FLAG.

**Gợi ý:** [HMAC collisions](https://en.wikipedia.org/wiki/PBKDF2#HMAC_collisions), để trả về toàn bộ FLAG thì mật khẩu 2 phải bắt đầu bằng 2 byte 0000H.


## Crypto-4 - Fifty-Fifty Chance
Một server dùng thuật toán chữ ký số trên đường cong Elliptic P-256 để ký `KCSC`. Server cho phép 2 lựa chọn là `flip` 1 bit ở `index` của `private_key` (d) và trả về chữ ký bị lỗi, `guess` `private_key`, nếu đúng sẽ trả về FLAG.

**Gợi ý**: [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm).
Khi lật một bit ở thứ tự i (đếm từ 0), thu được:
(r,ŝ) với:

r = `x(`k x G`)`, ŝ = (z + rd ± r2<sup>i</sup>)k<sup>-1</sup> mod n.

Tính được û<sub>1</sub> = zŝ<sup>-1</sup> mod n và û<sub>2</sub> = rŝ<sup>-1</sup> mod n.

So sánh `x(`û<sub>1</sub> x G + û<sub>2</sub> x Q + r2<sup>i</sup>ŝ<sup>-1</sup> x G`)` với `r` sẽ tìm được bit thứ i của `private_key`. Phần này mình để mọi người tự chứng minh.

**Lưu ý:** Trong bài mình sử dụng `fastecdsa` P-256, mặc định dữ liệu được ký sẽ được hash bằng sha256 chứ không giữ nguyên nhé...


## Crypto-5 - Weird Circle
Bài này nói về mã hóa AES bằng khóa được sinh từ một điểm thuộc [đường tròn](https://en.wikipedia.org/wiki/Edwards_curve#An_analogue_on_the_circle). Cho biết số nguyên tố p, điểm G, d x G, yêu cầu nhập một điểm bất kì Q thuộc đường tròn, điểm tạo khóa được tính bằng K = d x G + Q. Yêu cầu K không phải 4 điểm (1,0), (0,1), (-1,0), (0,-1) vì 4 điểm này không khó để tìm khi biết d x G.

**Gợi ý:** Nhập một điểm Q sao cho K có bậc n nhỏ, khóa có thể là một điểm thuộc nhóm sinh bới K, <K> = {0K, 1K, 2K, ... , (n-1)K}. K có thể là các điểm có góc là π/6, -π/4, π/3,... Như vậy phải đưa tọa độ của điểm này về đường tròn trong **Z**<sub>p</sub>. Một điểm P(x,y) có điểm đối là -P = (-x,y). Điểm Q cần nhập sẽ là Q = K - (d x G).

#
Phần trên là gợi ý cho các thử thách Cryptography, các bạn có hướng giải khác hoặc writeup hoàn chỉnh có thể gửi về cho fanpage nè. Nếu có sai sót hoặc thắc mắc nào các bạn hãy phản hồi cho mình nhé.

Cảm ơn các bạn đã đọc.
