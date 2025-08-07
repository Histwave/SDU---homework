import cv2
import numpy as np
from matplotlib import pyplot as plt


class DCTWatermark:
    def __init__(self, strength=25, block_size=8):
        self.strength = strength  # 水印强度
        self.block_size = block_size  # DCT分块大小

    def _preprocess_watermark(self, wm):
        """预处理水印图像为二值图像"""
        if wm.ndim == 3:
            wm = cv2.cvtColor(wm, cv2.COLOR_BGR2GRAY)
        _, binary_wm = cv2.threshold(wm, 127, 1, cv2.THRESH_BINARY)
        return binary_wm

    def embed(self, host, watermark):
        """
        嵌入水印
        :param host: 宿主图像 (BGR格式)
        :param watermark: 水印图像 (二值图像)
        :return: 含水印图像
        """
        # 预处理
        host_yuv = cv2.cvtColor(host, cv2.COLOR_BGR2YUV)
        y, u, v = cv2.split(host_yuv)
        wm = self._preprocess_watermark(watermark)

        # 调整水印尺寸
        h, w = y.shape
        wm = cv2.resize(wm, (w // self.block_size, h // self.block_size))

        # 分块处理
        watermarked_y = np.float32(y.copy())
        for i in range(0, h, self.block_size):
            for j in range(0, w, self.block_size):
                if i // self.block_size >= wm.shape[0] or j // self.block_size >= wm.shape[1]:
                    continue

                # DCT变换
                block = watermarked_y[i:i + self.block_size, j:j + self.block_size]
                dct_block = cv2.dct(block)

                # 嵌入水印到中频系数 (位置(4,1)和(3,2))
                wm_bit = wm[i // self.block_size, j // self.block_size]
                if wm_bit == 1:
                    dct_block[4, 1] += self.strength
                    dct_block[3, 2] -= self.strength
                else:
                    dct_block[4, 1] -= self.strength
                    dct_block[3, 2] += self.strength

                # IDCT变换
                watermarked_y[i:i + self.block_size, j:j + self.block_size] = cv2.idct(dct_block)

        # 合并通道
        watermarked = cv2.merge([np.uint8(watermarked_y), u, v])
        return cv2.cvtColor(watermarked, cv2.COLOR_YUV2BGR)

    def extract(self, watermarked_img, orig_size):
        """
        提取水印
        :param watermarked_img: 含水印图像
        :param orig_size: 原始水印尺寸 (h, w)
        :return: 提取的水印图像
        """
        # 预处理
        wm_h, wm_w = orig_size
        watermarked_yuv = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YUV)
        y, _, _ = cv2.split(watermarked_yuv)

        # 创建空水印
        extracted_wm = np.zeros((y.shape[0] // self.block_size,
                                 y.shape[1] // self.block_size), dtype=np.uint8)

        # 分块提取
        for i in range(0, y.shape[0], self.block_size):
            for j in range(0, y.shape[1], self.block_size):
                if i // self.block_size >= extracted_wm.shape[0] or j // self.block_size >= extracted_wm.shape[1]:
                    continue

                # DCT变换
                block = np.float32(y[i:i + self.block_size, j:j + self.block_size])
                dct_block = cv2.dct(block)

                # 提取水印
                diff = dct_block[4, 1] - dct_block[3, 2]
                extracted_wm[i // self.block_size, j // self.block_size] = 1 if diff > 0 else 0

        # 调整尺寸
        return cv2.resize(extracted_wm * 255, (wm_w, wm_h))


# 测试代码
if __name__ == "__main__":
    # 1. 加载图像和水印
    host = cv2.imread('host_image.jpg')
    wm = cv2.imread('watermark.png', cv2.IMREAD_GRAYSCALE)

    # 2. 创建水印对象并嵌入
    embedder = DCTWatermark(strength=30)
    watermarked = embedder.embed(host, wm)
    cv2.imwrite('watermarked.jpg', watermarked)

    # 3. 提取水印
    extractor = DCTWatermark(strength=30)
    extracted = extractor.extract(watermarked, wm.shape)
    cv2.imwrite('extracted_wm.png', extracted)

    # 4. 鲁棒性测试
    attacks = {
        'Rotate 30 degrees': lambda img: cv2.warpAffine(img,
                                               cv2.getRotationMatrix2D((img.shape[1] // 2, img.shape[0] // 2), 30, 1),
                                               img.shape[1::-1]),
        'Flip horizontally': lambda img: cv2.flip(img, 1),
        'Crop 20%': lambda img: img[int(img.shape[0] * 0.1):int(img.shape[0] * 0.9),
        int(img.shape[1] * 0.1):int(img.shape[1] * 0.9)],
        'Contrast ratio 50%': lambda img: cv2.convertScaleAbs(img, alpha=1.5, beta=0),
        'Gaussian noise': lambda img: cv2.add(img, np.random.normal(0, 25, img.shape).astype(np.uint8))
    }

    # 测试各种攻击下的水印提取
    results = []
    for name, attack in attacks.items():
        attacked_img = attack(watermarked)
        attacked_wm = extractor.extract(attacked_img, wm.shape)

        # 计算相似度
        similarity = np.mean(extracted == attacked_wm) * 100
        print(f"{name}后基础相似度: {similarity:.2f}%")

        # 计算比特错误率(BER)
        orig_wm = cv2.imread('watermark.png', cv2.IMREAD_GRAYSCALE)
        total_bits = orig_wm.size
        error_bits = np.sum(attacked_wm != extracted)
        ber = error_bits / total_bits
        print(f"比特错误率: {ber * 100:.2f}%")

        results.append((name, attacked_img, attacked_wm, similarity))

        # 保存结果
        cv2.imwrite(f'attacked_{name}.jpg', attacked_img)
        cv2.imwrite(f'wm_after_{name}.png', attacked_wm)

    # 显示结果
    plt.figure(figsize=(15, 10))
    for i, (name, img, wm_img, sim) in enumerate(results):
        plt.subplot(2, 3, i + 1)
        plt.imshow(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
        plt.title(f'{name}\nsimilarity: {sim:.2f}%')
        plt.axis('off')
    plt.tight_layout()
    plt.savefig('robustness_test.jpg')
    plt.show()

