import jsQR from 'jsqr';

export interface DecodedQrResult {
  data: string;
  isUpi: boolean;
  isUrl: boolean;
}

export function decodeQrFromImageData(
  data: Uint8ClampedArray,
  width: number,
  height: number
): DecodedQrResult | null {
  try {
    const code = jsQR(data, width, height);
    if (!code || !code.data) return null;

    const raw = code.data.trim();
    return {
      data: raw,
      isUpi: raw.toLowerCase().startsWith('upi://'),
      isUrl: /^https?:\/\//i.test(raw),
    };
  } catch {
    return null;
  }
}

export interface OcrResult {
  text: string;
  confidence: number;
  lowConfidence: boolean;
  notice?: string;
  qrPayload?: string;
  words: { text: string; confidence: number }[];
}

export interface ImagePreprocessingOptions {
  grayscale?: boolean;
  contrast?: number; // 0 - 2 (1 = normal)
  threshold?: number; // 0 - 255
  scaleFactor?: number;
}

/**
 * Preprocesses image on an offscreen HTML Canvas:
 * 1. Grayscale conversion (0.299*R + 0.587*G + 0.114*B)
 * 2. Contrast enhancement
 * 3. Thresholding for crisp text edges
 * 4. Upscaling small images
 */
export function preprocessCanvas(
  canvas: HTMLCanvasElement,
  options: ImagePreprocessingOptions = {}
): HTMLCanvasElement {
  const ctx = canvas.getContext('2d');
  if (!ctx) return canvas;

  const width = canvas.width;
  const height = canvas.height;
  const imgData = ctx.getImageData(0, 0, width, height);
  const data = imgData.data;

  const contrast = options.contrast ?? 1.2;
  const factor = (259 * (contrast * 255 + 255)) / (255 * (259 - contrast * 255));
  const threshold = options.threshold ?? 140;

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];

    // Grayscale luminance
    const gray = 0.299 * r + 0.587 * g + 0.114 * b;

    // Contrast adjustment
    let adjusted = factor * (gray - 128) + 128;
    adjusted = Math.max(0, Math.min(255, adjusted));

    // Thresholding
    const val = adjusted >= threshold ? 255 : 0;

    data[i] = val;
    data[i + 1] = val;
    data[i + 2] = val;
  }

  ctx.putImageData(imgData, 0, 0);
  return canvas;
}

/**
 * Evaluates OCR confidence and emits OCR_LOW_CONFIDENCE notice if required.
 */
export function evaluateOcrConfidence(text: string, rawConfidence: number): {
  lowConfidence: boolean;
  notice?: string;
} {
  const trimmed = text.trim();
  const isLow = rawConfidence < 65 || trimmed.length < 15;

  return {
    lowConfidence: isLow,
    notice: isLow
      ? 'OCR_LOW_CONFIDENCE: Extracted text may contain recognition inaccuracies. Please verify and edit the text before scanning.'
      : undefined,
  };
}

export class OcrService {
  /**
   * Reads an image File or Blob, renders to canvas, applies preprocessing,
   * extracts text via Tesseract.js, and immediately purges image data.
   */
  static async extractTextFromImage(
    file: File | Blob,
    onProgress?: (progress: number, status: string) => void
  ): Promise<OcrResult> {
    // Dynamically load Tesseract so initial page load remains instantaneous
    const { createWorker } = await import('tesseract.js');

    onProgress?.(10, 'Initializing OCR engine...');
    const worker = await createWorker('eng');

    try {
      onProgress?.(30, 'Preprocessing image...');

      // Load image into bitmap
      let imageSource: ImageBitmap | HTMLImageElement;
      if (typeof createImageBitmap !== 'undefined') {
        imageSource = await createImageBitmap(file);
      } else {
        imageSource = await new Promise<HTMLImageElement>((resolve, reject) => {
          const img = new Image();
          img.onload = () => resolve(img);
          img.onerror = reject;
          img.src = URL.createObjectURL(file);
        });
      }

      // Render to offscreen canvas
      const canvas = document.createElement('canvas');
      const scale = imageSource.width < 800 ? 1.5 : 1.0;
      canvas.width = imageSource.width * scale;
      canvas.height = imageSource.height * scale;

      let qrPayload: string | undefined;

      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.drawImage(imageSource, 0, 0, canvas.width, canvas.height);

        // Attempt QR code decoding prior to destructive thresholding
        const rawImgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const qrResult = decodeQrFromImageData(
          rawImgData.data,
          rawImgData.width,
          rawImgData.height
        );
        if (qrResult) {
          qrPayload = qrResult.data;
        }

        preprocessCanvas(canvas, { contrast: 1.1, threshold: 130 });
      }

      onProgress?.(50, 'Recognizing text...');
      const ret = await worker.recognize(canvas);

      onProgress?.(90, 'Validating output...');
      const cleanedText = ret.data.text.replace(/\r\n/g, '\n').trim();
      const avgConfidence = ret.data.confidence || 0;

      const confCheck = evaluateOcrConfidence(cleanedText, avgConfidence);

      const dataWithWords = ret.data as unknown as {
        words?: { text: string; confidence: number }[];
      };
      const words = (dataWithWords.words || []).map((w) => ({
        text: w.text,
        confidence: w.confidence,
      }));

      onProgress?.(100, 'Complete');

      // Purge image elements from memory immediately (Privacy guarantee)
      canvas.width = 0;
      canvas.height = 0;

      let finalText = cleanedText;
      let finalConfidence = avgConfidence;
      let finalLowConfidence = confCheck.lowConfidence;
      let finalNotice = confCheck.notice;

      if (qrPayload) {
        finalText = `[Decoded QR Code Destination]: ${qrPayload}${
          cleanedText ? '\n\n' + cleanedText : ''
        }`;
        finalConfidence = 99; // Reed-Solomon guaranteed checksum
        finalLowConfidence = false;
        finalNotice = undefined;
      }

      return {
        text: finalText,
        confidence: finalConfidence,
        lowConfidence: finalLowConfidence,
        notice: finalNotice,
        qrPayload,
        words,
      };
    } finally {
      await worker.terminate();
    }
  }
}
