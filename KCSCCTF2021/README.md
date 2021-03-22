# Hướng giải một số thử thách Cryptography KCSC CTF 2021.
## Crypto 1
Cho biết `FLAG` bắt đầu bằng 4 byte `KCSC`, một S-box 256 phần tử đóng vai trò là phép thế. Khóa có độ dài là 1 byte (vì mod 256 nên khóa thuộc đoạn [0,255]).
`FLAG` sẽ được biến đổi qua 256 vòng lặp, mỗi vòng thực hiện cập nhật khóa, XOR bản rõ với khóa và phép thay thế.

Các biến đổi trên `FLAG` hoàn toàn có thể đảo ngược lại, **gợi ý:** tạo một S-box<sup>-1</sup> ngược với S-box ban đầu, quết cạn khóa từ 0 đến 255, mỗi vòng lặp làm ngược lại với lúc mã hóa (S-box<sup>-1</sup>, XOR, cập nhật khóa).
