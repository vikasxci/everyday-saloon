const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'hadlay-kalan',
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
    transformation: [{ width: 200, height: 200, crop: 'fill', gravity: 'face', quality: 'auto:low', fetch_format: 'jpg' }]
  }
});

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

module.exports = upload;
