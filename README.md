Cấu trúc thư mục

📁 project/
├── app.py                  # File chính chạy Flask server
├── file_transfer.db        # CSDL SQLite
├── public_key.pem          # Khóa công khai (RSA)
├── private_key.pem         # Khóa riêng (RSA)
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── index.html
│   ├── contacts.html
│   └── history.html
└── uploads/                # Chứa các file được tải lên


Mục tiêu của bài

Đăng ký và đăng nhập tài khoản.

Quản lý danh bạ với khóa công khai.

Ký số file bằng khóa bí mật (RSA).

Gửi file và lưu trữ thông tin giao dịch.

Xác minh tính toàn vẹn và xác thực của file bằng khóa công khai.

Xem lại lịch sử các giao dịch đã thực hiện.

| Tính năng                | Mô tả                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------- |
| 🔑 **Đăng ký/Đăng nhập** | Người dùng có thể tạo tài khoản và đăng nhập vào hệ thống.                         |
| 👥 **Quản lý liên hệ**   | Cho phép thêm danh bạ người nhận, lưu trữ khóa công khai RSA.                      |
| 📁 **Tải file & ký số**  | File được ký bằng khóa riêng, sinh chữ ký số và hash SHA-256.                      |
| ✅ **Xác minh chữ ký**    | Người nhận có thể kiểm tra xem file có bị thay đổi không, xác thực được nguồn gửi. |
| 📜 **Xem lịch sử**       | Hiển thị danh sách các file đã ký và gửi.                                          |
