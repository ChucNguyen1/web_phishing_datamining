# Phishing Website Detection - Báo cáo kiểm tra chạy Notebook

## 1. Mục tiêu kiểm tra

File này ghi lại kết quả chạy lại toàn bộ các cell code trong notebook `Phishing_Website_Detection.ipynb` để xác nhận notebook hoạt động đúng end-to-end.

## 2. Trạng thái chung

- Kernel Python đã khởi động và hoạt động bình thường.
- Tất cả cell code trong luồng chính đã chạy thành công theo thứ tự.
- Các biểu đồ (validation curve, feature importance, RF n_estimators) hiển thị đúng.

## 3. Tóm tắt theo giai đoạn

### Giai đoạn A: Setup và đọc dữ liệu

- Import thư viện thành công: `liac-arff`, `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `seaborn`.
- Đọc dữ liệu ARFF thành công từ `Training Dataset.arff`.
- Kích thước dữ liệu: **(11055, 31)**.
- Toàn bộ cột đã ở dạng số sau bước ép kiểu (`int64/int32`).

### Giai đoạn B: Tiền xử lý

- Missing values: **0** ở tất cả cột.
- Gộp nhãn `0 -> -1` (Suspicious gộp vào Phishing).
- Phân bố nhãn sau gộp:
  - `-1`: 4898
  - `1`: 6157
- Chia train/test theo tỉ lệ 80/20 với stratify:
  - `X_train`: (8844, 30)
  - `X_test`: (2211, 30)

### Giai đoạn C: Baseline models

#### Decision Tree Baseline

- Accuracy: **0.9711**
- Precision: **0.9702**
- Recall: **0.9781**
- F1-score: **0.9741**

#### Random Forest Baseline

- Accuracy: **0.9742**
- Precision: **0.9696**
- Recall: **0.9846**
- F1-score: **0.9770**

Nhận xét nhanh:

- RF baseline nhỉnh hơn DT baseline ở F1-score.

### Giai đoạn D: Tuning Decision Tree

- Đã chạy validation curve theo `max_depth` và hiển thị biểu đồ đúng.
- GridSearchCV cho DT chạy thành công.
- Best DT:
  - `criterion='gini'`
  - `max_depth=15`
  - `min_samples_leaf=1`
- Kết quả best DT:
  - Train F1: **0.9851**
  - Test F1: **0.9659**

Nhận xét:

- Best DT theo GridSearch trong cấu hình hiện tại cho Test F1 thấp hơn DT baseline, có dấu hiệu overfit/khác biệt do không gian tham số và tiêu chí chọn.

### Giai đoạn E: Tuning Random Forest

- Đã khảo sát `n_estimators` và hiển thị biểu đồ đúng.
- GridSearchCV cho RF chạy thành công.
- Best RF:
  - `max_depth=15`
  - `max_features=None`
  - `min_samples_leaf=1`
  - `n_estimators=100`
- Kết quả best RF:
  - Train F1: **0.9900**
  - Test F1: **0.9772**

Nhận xét:

- RF tiếp tục là mô hình tốt nhất trong notebook này.

## 4. Feature importance (kết quả nổi bật)

### Decision Tree - Top feature

1. `SSLfinal_State`
2. `URL_of_Anchor`
3. `Links_in_tags`

### Random Forest - Top feature

1. `SSLfinal_State`
2. `URL_of_Anchor`
3. `Links_in_tags`

Nhận xét:

- Hai mô hình nhất quán về các đặc trưng quan trọng nhất.

## 5. Bảng so sánh cuối cùng (F1-score)

- RF Best (GridSearch): **0.977154**
- RF Baseline: **0.977025**
- DT Baseline: **0.974110**
- DT Best (GridSearch): **0.965932**

Kết luận ngắn:

- Mô hình khuyến nghị hiện tại: **Random Forest**.
- Toàn bộ notebook đã chạy được và tái lập kết quả thành công.

## 6. Ghi chú kỹ thuật

- Đã thay cell đọc dữ liệu bị gán sai language về Python để đảm bảo thực thi được.
- Sau khi sửa, luồng chạy đã ổn định và không còn lỗi NameError trong pipeline chính.
