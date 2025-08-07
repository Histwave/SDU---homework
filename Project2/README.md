# Project2 基于数字水印的图片泄露检测

## 一、实验背景
基于数字水印的图片泄露检测，既能在图片被篡改、传播时留存 “隐形证据”，辅助版权维权，又能精准定位泄露源头，锁定责任方，助力优化信息管理流程，降低敏感内容扩散风险，为图片安全筑起技术防线。
## 二、实验目的
编程实现图片水印嵌入和提取（可依托开源项目二次开发），并进行鲁棒性测试，包括不限于翻转、平移、截取、调对比度等。
## 三、实验原理
基于**DCT（离散余弦变换）的盲水印算法**，核心原理如下：
1.  **频域嵌入**：  
    将图像转换到频域（DCT域），在**中频系数**中嵌入水印（避免高频易被过滤、低频影响视觉质量）。
    
2.  **系数差分调制**：
    
    -   选择两个固定位置的中频系数  `(4,1)`  和  `(3,2)`
        
    -   嵌入规则：
        
        --   水印比特=1：增大  `dct_block[4,1]`，减小  `dct_block[3,2]`
            
        --   水印比特=0：减小  `dct_block[4,1]`，增大  `dct_block[3,2]`
            
    -   提取时通过比较两个系数的相对大小判断水印比特
        
3.  **分块处理**：  
    将图像分割为 8×8 块，每个块嵌入1个水印比特，实现水印分散分布。
    
4.  **颜色空间转换**：  
    在YUV空间的亮度分量（Y通道）嵌入水印，减少对颜色的影响。
## 四、实验思路及过程
1.  **水印嵌入**：
    
    -   宿主图像 → YUV → 提取Y通道
        
    -   水印图像 → 二值化 → 缩放至  `(height/8, width/8)`
        
    -   对每个8×8Y通道块：
        
        --   DCT变换 → 按规则修改系数 → IDCT逆变换
            
    -   合并通道 → 输出含水印图像
        
2.  **水印提取**：
    
    -   含水印图像 → YUV → 提取Y通道
        
    -   对每个8×8块：
        
        -- DCT变换 → 比较  `(4,1)`  和  `(3,2)`  系数差值 → 判定水印比特
            
    -   重组比特矩阵 → 缩放至原始水印尺寸
        
3.  **鲁棒性测试**：
    
    -   设计常见攻击（旋转/翻转/裁剪/对比度/噪声）
        
    -   计算相似度（像素匹配率）和比特错误率（BER）
 
 ### 具体实现如下：
 #### 1. 预处理
```cpp
def _preprocess_watermark(self, wm):
    if wm.ndim == 3:  # 彩色转灰度
        wm = cv2.cvtColor(wm, cv2.COLOR_BGR2GRAY)
    _, binary_wm = cv2.threshold(wm, 127, 1, cv2.THRESH_BINARY)  # 二值化(0/1)
    return binary_wm
```
#### 2. 水印嵌入
```cpp
# 关键步骤
for i in range(0, h, self.block_size):
    for j in range(0, w, self.block_size):
        # 获取当前块
        block = watermarked_y[i:i+8, j:j+8]
        
        # DCT变换 (需转为float32)
        dct_block = cv2.dct(np.float32(block))
        
        # 嵌入逻辑
        if wm_bit == 1:
            dct_block[4, 1] += self.strength  # 增强系数
            dct_block[3, 2] -= self.strength   # 减弱系数
        else:
            dct_block[4, 1] -= self.strength
            dct_block[3, 2] += self.strength
        
        # 逆变换
        watermarked_y[i:i+8, j:j+8] = cv2.idct(dct_block)
```
#### 3. 水印提取
```cpp
# 关键步骤
for i in range(0, y.shape[0], self.block_size):
    for j in range(0, y.shape[1], self.block_size):
        # DCT变换
        dct_block = cv2.dct(np.float32(block))
        
        # 提取逻辑：比较系数差值
        diff = dct_block[4, 1] - dct_block[3, 2]
        extracted_wm[i//8, j//8] = 1 if diff > 0 else 0
```
#### 4. 鲁棒性测试
```cpp
attacks = {
    'Rotate 30 degrees': lambda img: cv2.warpAffine(...),
    'Flip horizontally': lambda img: cv2.flip(img, 1),
    'Crop 20%': lambda img: img[10%:90%, 10%:90%],
    'Contrast ratio 50%': lambda img: cv2.convertScaleAbs(img, alpha=1.5),
    'Gaussian noise': lambda img: img + np.random.normal(0, 25, img.shape)
}
```
#### 5. 评估指标
```cpp
# 相似度 (像素级匹配率)
similarity = np.mean(extracted == attacked_wm) * 100

# 比特错误率 (BER)
total_bits = orig_wm.size
error_bits = np.sum(attacked_wm != extracted)
ber = error_bits / total_bits
```
## 五、实验结果
### 初始文件说明：
1. **host_image.jpg**：作为承载水印的原始载体图像。
2. **watermark.png**：要嵌入到宿主图像中的数字水印。

### 输出文件说明：
#### 1. 基础文件
|文件名|说明|
|-|-|
|watermarked.jpg|嵌入水印后的宿主图像|
|extracted_wm.png|提取的水印图像|
#### 2. 攻击测试生成的文件

针对每种攻击会生成两类文件：

 A. 攻击后的宿主图像：
 |文件名|攻击类型|
 |-|-|
 |attacked_Contrast ratio 50%.jpg|对比度+50%|
 |attacked_Crop 20%.jpg|裁剪20%|
 |attacked_Flip horizontally.jpg|水平翻转|
 |attacked_Gaussian noise.jpg|高斯噪声|
 |attacked_Rotate 30 degrees.jpg|旋转30度|
 
 B. 从攻击图像提取的水印
 |文件名|攻击类型|
 |-|-|
 |wm_after_Contrast ratio 50%.png|对比度+50%|
 |wm_after_Crop 20%.png|裁剪20%|
 |wm_after_Flip horizontally.png|水平翻转|
 |wm_after_Gaussian noise.png|高斯噪声|
 |wm_after_Rotate 30 degrees.png|旋转30度|
 
C.汇总分析文件
|文件名|说明|
|-|-|
|robustness_test.jpg|鲁棒性测试结果汇总图，标注每种攻击的水印相似度|

### 鲁棒性评估结果
结果在project2-output.png中，如图所示，该算法在防护对比度增加、高斯噪声时表现较好，而在防护图片旋转、水平翻转、裁剪时表现较差。
