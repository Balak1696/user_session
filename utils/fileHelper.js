const {
    S3Client,
    DeleteObjectCommand,
    HeadObjectCommand,
    ListObjectsV2Command,
    DeleteObjectsCommand
  } = require('@aws-sdk/client-s3');
  const multer = require('multer');
  const multerS3 = require('multer-s3');

  const path = require('path');
  require('dotenv').config();
  
  const s3 = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
  });
  const PROFILE_PICTURES_SIZE= 2 * 1024 * 1024;
  const allowedImageTypes = ['image/jpeg', 'image/png'];
  const allowedExtensions_Profile = ['.jpg', '.jpeg', '.png'];
  
  const MAX_IMAGE_SIZE = 5 * 1024 * 1024; 
  const MAX_VIDEO_SIZE = 10 * 1024 * 1024; 
  
  const imageTypes = ['image/jpeg', 'image/png'];
  const videoTypes = ['video/mp4', 'video/x-matroska'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.mp4', '.mkv'];
  const profile_pictures_fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const mime = file.mimetype;
  
    if (!allowedImageTypes.includes(mime)) {
      return cb(new Error('Only JPG and PNG image files are allowed'), false);
    }
  
    if (!allowedExtensions_Profile.includes(ext)) {
      return cb(new Error('Invalid file extension. Use JPG or PNG only'), false);
    }
  
    cb(null, true);
  };
  const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const mime = file.mimetype;
  
    const isImage = imageTypes.includes(mime);
    const isVideo = videoTypes.includes(mime);
  
    if (!isImage && !isVideo) {
      return cb(new Error('Only JPG, PNG, MP4, and MKV files are allowed'), false);
    }
  
    if (!allowedExtensions.includes(ext)) {
      return cb(new Error('Only JPG, PNG, MP4, and MKV file extensions are allowed'), false);
    }
  
    cb(null, true);
  };
  const upload = multer({
    storage: multerS3({
      s3: s3,
      bucket: process.env.S3_BUCKET_NAME,
      contentType: multerS3.AUTO_CONTENT_TYPE,
      acl: 'public-read',
      key: (req, file, cb) => {
                    const safeName = file.originalname.replace(/\s+/g, '_');
                    const folder = 'products';
                    const fileName = `${Date.now()}_${safeName}`;
                    const fullPath = `${folder}/${fileName}`;
                    cb(null, fullPath);
                  },
    }),

    fileFilter,
    limits: {
      fileSize: MAX_VIDEO_SIZE,
      files: 5,
    },
  });
  const getImageUrl = async (ticketId, filename) => {
    const key = `${ticketId}/${filename}`;
    const headCommand = new HeadObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
    });
  
    await s3.send(headCommand);
  
    return `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
  };
  
  const deleteS3Folder = async (productId) => {
    try {
      const listParams = {
        Bucket: process.env.S3_BUCKET_NAME,
        Prefix: `${productId}/`, 
      };
      const listCommand = new ListObjectsV2Command(listParams);
      const listResponse = await s3.send(listCommand);
      if (!listResponse.Contents || listResponse.Contents.length === 0) {
        console.log('No files found to delete in folder:', productId);
        return;
      }
      const objectsToDelete = listResponse.Contents.map(obj => ({ Key: obj.Key }));
      const deleteParams = {
        Bucket: process.env.S3_BUCKET_NAME,
        Delete: {
          Objects: objectsToDelete,
          Quiet: true,
        },
      };
      const deleteCommand = new DeleteObjectsCommand(deleteParams);
      await s3.send(deleteCommand);
      console.log(`Successfully deleted S3 folder: ${productId}/`);
    } catch (error) {
      console.error('Error deleting S3 folder:', error);
      throw error;
    }
  };
  const deleteFileFromS3 = async (key) => {
    if (!key) throw new Error("Missing S3 object key");
  
    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
    };
  
    try {
      const command = new DeleteObjectCommand(params);
      await s3.send(command);
      console.log(`S3 File Deleted: ${key}`);
    } catch (err) {
      console.error('Error deleting file from S3:', err);
      throw err;
    }
  };
  const createProfilePictureUpload = (firstName, lastName) => {
    const folderName = `${firstName.trim().toLowerCase()}-${lastName.trim().toLowerCase()}`;
  
    return multer({
      storage: multerS3({
        s3: s3,
        bucket: process.env.S3_BUCKET_NAME,
        contentType: multerS3.AUTO_CONTENT_TYPE,
        acl: 'public-read',
        key: (req, file, cb) => {
          try {
            const uniqueFilename = `${Date.now()}-${file.originalname}`;
            const key = `profile_pictures/${folderName}/${uniqueFilename}`;
  
            req.profilePictureKey = key;
  
            cb(null, key);
          } catch (err) {
            cb(err);
          }
        },
      }),
      fileFilter: profile_pictures_fileFilter,
      limits: {
        fileSize: PROFILE_PICTURES_SIZE,
        files: 1,
      },
    });
  };
  
  module.exports = {
    upload,
    getImageUrl,
    deleteS3Folder,
    deleteFileFromS3,
    createProfilePictureUpload,
    MAX_IMAGE_SIZE,
    MAX_VIDEO_SIZE,
    PROFILE_PICTURES_SIZE,
    imageTypes,
    videoTypes,
    allowedImageTypes,
    allowedExtensions,
    allowedExtensions_Profile
   
  };
  